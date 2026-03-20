// Package middleware provides an HTTP authentication middleware for Go
// high-concurrency servers.
//
// Two authentication flows are supported:
//
// Situation A – Bearer JWT token
//
//	Authorization: Bearer <token>
//
// The middleware validates the JWT, extracts the "uin" claim, and compares it
// with the "uin" field in the JSON request body.  On success the request is
// forwarded to the next handler unchanged.
//
// Situation B – X-Launcher-Signature
//
//	X-Launcher-Signature: <base64-encoded payload>
//
// The payload decodes to: uin(8B) | timestamp(8B) | signature(64B).
// The middleware checks the timestamp (±300 s), verifies the Ed25519 signature
// over uin+timestamp, checks the body uin, generates a JWT and returns
// it in the X-Set-Token response header, then forwards the request.
//
// Performance notes:
//   - The Ed25519 public key is pre-loaded once in Config; it is never
//     re-parsed inside the middleware hot-path.
//   - A TTL cache records recently seen signatures to reject replays cheaply
//     (without re-running Ed25519 verify).
package middleware

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// UINSize is the byte length of the uin field in the Situation B payload.
	UINSize = 8
	// TimestampSize is the byte length of the timestamp field.
	TimestampSize = 8
	// SignatureSize is the byte length of the Ed25519 signature.
	SignatureSize = 64
	// PayloadSize is the total expected decoded byte length for Situation B.
	PayloadSize = UINSize + TimestampSize + SignatureSize // 80

	// TokenExpiry is the lifetime of an issued access token.
	TokenExpiry = 72 * time.Hour
	// TokenRenewThreshold is the remaining-lifetime window within which a
	// still-valid Bearer token will be proactively renewed.  When the token
	// expires in less than this duration the middleware issues a fresh token
	// in the X-Set-Token response header so the client can replace it without
	// interruption.
	TokenRenewThreshold = 8 * time.Hour
	// TimestampTolerance is the maximum clock-skew / replay window (300 s).
	TimestampTolerance = 300 * time.Second
)

// Claims holds the JWT payload used by both token issuance and validation.
type Claims struct {
	UIN uint64 `json:"uin"`
	jwt.RegisteredClaims
}

// Config carries the immutable configuration for AuthMiddleware.
// Callers must populate PublicKey and JWTSecret before calling New.
type Config struct {
	// PublicKey is the Ed25519 public key used to verify X-Launcher-Signature
	// headers.  It must be pre-loaded by the caller; the middleware never parses
	// or derives it at request time.
	PublicKey ed25519.PublicKey

	// JWTSecret is the HMAC-SHA256 signing secret for JWT tokens.
	JWTSecret []byte
}

// AuthMiddleware is the stateful authentication middleware.  Create one instance
// per application (not per request) using New.
type AuthMiddleware struct {
	pubKey    ed25519.PublicKey
	jwtSecret []byte

	// cache records recently verified signatures to detect replays without
	// re-running the expensive Ed25519 verify operation.
	cache *sigCache
}

// New creates a new AuthMiddleware from cfg.  The returned middleware is safe
// for concurrent use.
func New(cfg Config) *AuthMiddleware {
	m := &AuthMiddleware{
		pubKey:    cfg.PublicKey,
		jwtSecret: cfg.JWTSecret,
		cache:     newSigCache(),
	}
	return m
}

// Handler wraps next with authentication.  It reads the request body once,
// replaces r.Body with a fresh reader so downstream handlers always see the
// original bytes, and writes X-Set-Token on successful Situation B verification.
func (m *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body once so we can inspect it without consuming it.
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusUnauthorized)
			return
		}
		// Restore body immediately so the next call always sees a fresh reader.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		if auth := r.Header.Get("Authorization"); auth != "" {
			m.handleBearerToken(w, r, next, auth, bodyBytes)
			return
		}

		if sig := r.Header.Get("X-Launcher-Signature"); sig != "" {
			m.handleLauncherSignature(w, r, next, sig, bodyBytes)
			return
		}

		fmt.Printf("[middleware] unauthorized: no auth header remote=%s path=%s\n", r.RemoteAddr, r.URL.Path)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

// handleBearerToken implements Situation A.
func (m *AuthMiddleware) handleBearerToken(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	authHeader string,
	bodyBytes []byte,
) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		fmt.Printf("[bearer] malformed authorization header remote=%s path=%s\n", r.RemoteAddr, r.URL.Path)
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}
	tokenStr := authHeader[len(prefix):]

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return m.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		fmt.Printf("[bearer] invalid token remote=%s path=%s err=%v\n", r.RemoteAddr, r.URL.Path, err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	bodyUIN, bodyCmd, err := extractUIN(bodyBytes)
	if err != nil {
		fmt.Printf("[bearer] failed to extract UIN from body remote=%s path=%s err=%v\n", r.RemoteAddr, r.URL.Path, err)
		http.Error(w, "invalid request body", http.StatusUnauthorized)
		return
	}

	if claims.UIN != bodyUIN && bodyCmd != "wtlogin.trans_emp" && bodyUIN != 0 {
		fmt.Printf("[bearer] UIN mismatch remote=%s path=%s token_uin=%d body_uin=%d cmd:%s\n", r.RemoteAddr, r.URL.Path, claims.UIN, bodyUIN, bodyCmd)
		http.Error(w, "uin mismatch", http.StatusUnauthorized)
		return
	}

	// Proactively renew the token when it will expire within TokenRenewThreshold
	// so the client always has a long-lived token without needing a re-auth.
	if claims.ExpiresAt != nil && time.Until(claims.ExpiresAt.Time) < TokenRenewThreshold {
		if newToken, err := m.generateToken(claims.UIN); err == nil {
			w.Header().Set("X-Set-Token", newToken)
			fmt.Printf("[bearer] token renewed proactively uin=%d remaining=%s\n", claims.UIN, time.Until(claims.ExpiresAt.Time))
		} else {
			fmt.Printf("[bearer] failed to generate renewal token uin=%d err=%v\n", claims.UIN, err)
		}
	}

	fmt.Printf("[bearer] auth OK uin=%d remote=%s path=%s\n", claims.UIN, r.RemoteAddr, r.URL.Path)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	next.ServeHTTP(w, r)
}

// handleLauncherSignature implements Situation B.
func (m *AuthMiddleware) handleLauncherSignature(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
	sigHeader string,
	bodyBytes []byte,
) {
	// --- 1. Decode base64 payload ---
	decoded, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil || len(decoded) < PayloadSize {
		fmt.Printf("[launcher-sig] failed to decode header remote=%s path=%s err=%v\n", r.RemoteAddr, r.URL.Path, err)
		http.Error(w, "invalid signature header", http.StatusUnauthorized)
		return
	}
	// Keep a fixed-size copy.
	var payload [PayloadSize]byte
	copy(payload[:], decoded[:PayloadSize])

	// --- 2. Parse fields ---
	uin := binary.BigEndian.Uint64(payload[0:8])
	timestamp := int64(binary.BigEndian.Uint64(payload[8:16]))
	signature := payload[16:80]

	// --- 3. Timestamp check ---
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(TimestampTolerance.Seconds()) {
		fmt.Printf("[launcher-sig] timestamp expired remote=%s path=%s uin=%d diff_sec=%d\n", r.RemoteAddr, r.URL.Path, uin, diff)
		http.Error(w, "timestamp expired", http.StatusUnauthorized)
		return
	}

	// --- 4. Replay / cache check ---
	// The cache key is the raw 64-byte signature.  If it is already present
	// the request is a replay: reject it cheaply without re-running Ed25519.
	cacheKey := string(signature[:])
	if m.cache.has(cacheKey) {
		fmt.Printf("[launcher-sig] replayed signature remote=%s path=%s uin=%d\n", r.RemoteAddr, r.URL.Path, uin)
		http.Error(w, "replayed signature", http.StatusUnauthorized)
		return
	}

	// --- 5. Ed25519 signature verification ---
	// The signed message is uin(8B) || timestamp(8B).
	message := payload[0:16]
	if !ed25519.Verify(m.pubKey, message, signature[:]) {
		fmt.Printf("[launcher-sig] Ed25519 verification failed remote=%s path=%s uin=%d\n", r.RemoteAddr, r.URL.Path, uin)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// --- 6. Body UIN check ---
	bodyUIN, bodyCmd, err := extractUIN(bodyBytes)
	if err != nil {
		fmt.Printf("[launcher-sig] failed to extract UIN from body remote=%s path=%s err=%v\n", r.RemoteAddr, r.URL.Path, err)
		http.Error(w, "invalid request body", http.StatusUnauthorized)
		return
	}

	if uin != bodyUIN && bodyCmd != "wtlogin.trans_emp" && bodyUIN != 0 {
		fmt.Printf("[launcher-sig] UIN mismatch remote=%s path=%s sig_uin=%d body_uin=%d cmd=%s\n", r.RemoteAddr, r.URL.Path, uin, bodyUIN, bodyCmd)
		http.Error(w, "uin mismatch", http.StatusUnauthorized)
		return
	}

	// --- 7. Mark signature as used (anti-replay) and issue token ---
	m.cache.add(cacheKey, TimestampTolerance)

	tokenStr, err := m.generateToken(uin)
	if err != nil {
		fmt.Printf("[launcher-sig] failed to generate token uin=%d err=%v\n", uin, err)
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Set-Token", tokenStr)

	fmt.Printf("[launcher-sig] auth OK, token issued uin=%d remote=%s path=%s\n", uin, r.RemoteAddr, r.URL.Path)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	next.ServeHTTP(w, r)
}

// generateToken mints a signed JWT containing uin with a 2-hour expiry.
func (m *AuthMiddleware) generateToken(uin uint64) (string, error) {
	now := time.Now()
	claims := &Claims{
		UIN: uin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// RefreshHandler returns an http.Handler that only renews the JWT token.
// It validates the Bearer token in the Authorization header and, if the token
// will expire within TokenRenewThreshold, issues a fresh token in the
// X-Set-Token response header.  If the token is still fresh (more than
// TokenRenewThreshold remaining) it responds 200 with no X-Set-Token header.
// No request body is required and the request is NOT forwarded downstream.
func (m *AuthMiddleware) RefreshHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			fmt.Printf("[refresh] malformed authorization header remote=%s\n", r.RemoteAddr)
			http.Error(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}
		tokenStr := auth[len(prefix):]

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return m.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			fmt.Printf("[refresh] invalid token remote=%s err=%v\n", r.RemoteAddr, err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Only set X-Set-Token when the token is approaching expiry.
		if claims.ExpiresAt != nil && time.Until(claims.ExpiresAt.Time) < TokenRenewThreshold {
			if newToken, err := m.generateToken(claims.UIN); err == nil {
				w.Header().Set("X-Set-Token", newToken)
				fmt.Printf("[refresh] token renewed uin=%d remaining=%s\n", claims.UIN, time.Until(claims.ExpiresAt.Time))
			} else {
				fmt.Printf("[refresh] failed to generate token uin=%d err=%v\n", claims.UIN, err)
			}
		} else {
			fmt.Printf("[refresh] token still fresh, no renewal uin=%d remaining=%s\n", claims.UIN, time.Until(claims.ExpiresAt.Time))
		}

		w.WriteHeader(http.StatusOK)
	})
}

// Stop shuts down background goroutines started by the middleware (e.g. the
// replay-cache GC).  Call it when the server is shutting down to avoid goroutine
// leaks.  After Stop returns the middleware must not be used.
func (m *AuthMiddleware) Stop() {
	m.cache.stop()
}

// The field is expected to be a non-negative integer.
func extractUIN(body []byte) (uint64, string, error) {
	var req struct {
		UIN uint64 `json:"uin"`
		Cmd string `json:"command"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, "", err
	}
	return req.UIN, req.Cmd, nil
}
