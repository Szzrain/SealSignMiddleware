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
//	X-Launcher-Signature: <base2048-encoded payload>
//
// The payload decodes to: uin(8B) | timestamp(8B) | signature(64B).
// The middleware checks the timestamp (±300 s), verifies the Ed25519 signature
// over uin+timestamp, checks the body uin, generates a 2-hour JWT and returns
// it in the X-Set-Token response header, then forwards the request.
//
// Performance notes:
//   - The Ed25519 public key is pre-loaded once in Config; it is never
//     re-parsed inside the middleware hot-path.
//   - A sync.Pool recycles the 80-byte decode buffer used for Situation B.
//   - A TTL cache records recently seen signatures to reject replays cheaply
//     (without re-running Ed25519 verify).
package middleware

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
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
	TokenExpiry = 2 * time.Hour
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

	// bufPool recycles the fixed-size decode buffer used in Situation B to
	// avoid per-request heap allocations in the hot path.
	bufPool sync.Pool

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
	m.bufPool = sync.Pool{
		New: func() any {
			b := make([]byte, PayloadSize)
			return &b
		},
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
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	bodyUIN, err := extractUIN(bodyBytes)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusUnauthorized)
		return
	}
	if claims.UIN != bodyUIN {
		http.Error(w, "uin mismatch", http.StatusUnauthorized)
		return
	}

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
	// --- 1. Decode Base2048 payload, reusing pooled buffer ---
	bufPtr := m.bufPool.Get().(*[]byte)
	decoded, err := Base2048Decode(sigHeader, *bufPtr)
	if err != nil || len(decoded) < PayloadSize {
		m.bufPool.Put(bufPtr)
		http.Error(w, "invalid signature header", http.StatusUnauthorized)
		return
	}
	// Keep a fixed-size copy so we can return the buffer before the expensive
	// Ed25519 verification step.
	var payload [PayloadSize]byte
	copy(payload[:], decoded[:PayloadSize])
	// Update the backing slice pointer in case Base2048Decode reallocated.
	*bufPtr = decoded
	m.bufPool.Put(bufPtr)

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
		http.Error(w, "timestamp expired", http.StatusUnauthorized)
		return
	}

	// --- 4. Replay / cache check ---
	// The cache key is the raw 64-byte signature.  If it is already present
	// the request is a replay: reject it cheaply without re-running Ed25519.
	cacheKey := string(signature[:])
	if m.cache.has(cacheKey) {
		http.Error(w, "replayed signature", http.StatusUnauthorized)
		return
	}

	// --- 5. Ed25519 signature verification ---
	// The signed message is uin(8B) || timestamp(8B).
	message := payload[0:16]
	if !ed25519.Verify(m.pubKey, message, signature[:]) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// --- 6. Body UIN check ---
	bodyUIN, err := extractUIN(bodyBytes)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusUnauthorized)
		return
	}
	if uin != bodyUIN {
		http.Error(w, "uin mismatch", http.StatusUnauthorized)
		return
	}

	// --- 7. Mark signature as used (anti-replay) and issue token ---
	m.cache.add(cacheKey, TimestampTolerance)

	tokenStr, err := m.generateToken(uin)
	if err != nil {
		http.Error(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Set-Token", tokenStr)

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

// Stop shuts down background goroutines started by the middleware (e.g. the
// replay-cache GC).  Call it when the server is shutting down to avoid goroutine
// leaks.  After Stop returns the middleware must not be used.
func (m *AuthMiddleware) Stop() {
	m.cache.stop()
}

// The field is expected to be a non-negative integer.
func extractUIN(body []byte) (uint64, error) {
	var req struct {
		UIN uint64 `json:"uin"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return 0, err
	}
	return req.UIN, nil
}
