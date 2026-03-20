package middleware

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---- helpers ----------------------------------------------------------------

var (
	testPubKey  ed25519.PublicKey
	testPrivKey ed25519.PrivateKey
	testSecret  = []byte("test-jwt-secret-32-bytes-minimum!!")
)

func init() {
	var err error
	testPubKey, testPrivKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
}

func TestInit(t *testing.T) {
	if len(testPubKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid test public key size: got %d, want %d", len(testPubKey), ed25519.PublicKeySize)
	}
	if len(testPrivKey) != ed25519.PrivateKeySize {
		t.Fatalf("invalid test private key size: got %d, want %d", len(testPrivKey), ed25519.PrivateKeySize)
	}
	if len(testSecret) < 32 {
		t.Fatalf("test secret too short: got %d bytes, want at least 32", len(testSecret))
	}
	t.Logf("test public key: %x", testPubKey)
	t.Logf("test private key: %x", testPrivKey)
}

func newMiddleware() *AuthMiddleware {
	return New(Config{PublicKey: testPubKey, JWTSecret: testSecret})
}

// okHandler is a trivial downstream handler that echoes 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// buildSignatureHeader constructs a valid X-Launcher-Signature header value.
func buildSignatureHeader(privKey ed25519.PrivateKey, uin uint64, ts int64) string {
	payload := make([]byte, PayloadSize)
	binary.BigEndian.PutUint64(payload[0:8], uin)
	binary.BigEndian.PutUint64(payload[8:16], uint64(ts))
	sig := ed25519.Sign(privKey, payload[0:16])
	copy(payload[16:], sig)
	return base64.StdEncoding.EncodeToString(payload)
}

// buildBearerToken mints a valid JWT for uin using secret.
func buildBearerToken(uin uint64, secret []byte) string {
	now := time.Now()
	claims := &Claims{
		UIN: uin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, _ := token.SignedString(secret)
	return s
}

// body returns a JSON body with the given uin.
func body(uin uint64) *bytes.Reader {
	b, _ := json.Marshal(map[string]uint64{"uin": uin})
	return bytes.NewReader(b)
}

// ---- Base2048 ---------------------------------------------------------------

func TestBase2048RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0xFF},
		make([]byte, 80), // PayloadSize zeros
	}
	for i := range cases {
		// fill non-empty slices with pseudo-random data
		if len(cases[i]) > 0 {
			for j := range cases[i] {
				cases[i][j] = byte(i*17 + j*37)
			}
		}
		encoded := Base2048Encode(cases[i])
		decoded, err := Base2048Decode(encoded, nil)
		if err != nil {
			t.Fatalf("case %d decode error: %v", i, err)
		}
		if !bytes.Equal(cases[i], decoded) {
			t.Fatalf("case %d: got %v, want %v", i, decoded, cases[i])
		}
	}
}

func TestBase2048PoolReuse(t *testing.T) {
	src := make([]byte, PayloadSize)
	for i := range src {
		src[i] = byte(i)
	}
	encoded := Base2048Encode(src)

	buf := make([]byte, PayloadSize)
	decoded, err := Base2048Decode(encoded, buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, decoded) {
		t.Fatal("mismatch after pool reuse")
	}
}

func TestBase2048InvalidChar(t *testing.T) {
	// Build a valid encode, then corrupt one character.
	src := make([]byte, 80)
	enc := Base2048Encode(src)
	runes := []rune(enc)
	runes[0] = 'A' // 'A' is outside both tables
	corrupted := string(runes)
	_, err := Base2048Decode(corrupted, nil)
	if err == nil {
		t.Fatal("expected error for invalid character, got nil")
	}
}

// ---- Situation A: Bearer JWT ------------------------------------------------

func TestSituationA_ValidToken(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 12345678
	tokenStr := buildBearerToken(uin, testSecret)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSituationA_UINMismatch(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const tokenUIN uint64 = 111
	const bodyUIN uint64 = 222
	tokenStr := buildBearerToken(tokenUIN, testSecret)

	req := httptest.NewRequest(http.MethodPost, "/", body(bodyUIN))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestSituationA_InvalidToken(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", body(1))
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestSituationA_ExpiredToken(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 42
	now := time.Now().Add(-3 * time.Hour)
	claims := &Claims{
		UIN: uin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := token.SignedString(testSecret)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rr.Code)
	}
}

func TestSituationA_WrongSigningMethod(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 99
	// Sign with RS256 is not possible without an RSA key pair here, so we
	// tamper the header instead: supply a token signed with a different secret.
	tokenStr := buildBearerToken(uin, []byte("wrong-secret"))

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestSituationA_MissingBearerPrefix(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	tokenStr := buildBearerToken(1, testSecret)
	req := httptest.NewRequest(http.MethodPost, "/", body(1))
	req.Header.Set("Authorization", tokenStr) // missing "Bearer "
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// ---- Situation B: X-Launcher-Signature --------------------------------------

func TestSituationB_Valid(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 987654321
	ts := time.Now().Unix()
	sigHeader := buildSignatureHeader(testPrivKey, uin, ts)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("X-Launcher-Signature", sigHeader)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if tok := rr.Header().Get("X-Set-Token"); tok == "" {
		t.Fatal("expected X-Set-Token header to be set")
	}
}

func TestSituationB_TokenIsValid(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 555
	ts := time.Now().Unix()
	sigHeader := buildSignatureHeader(testPrivKey, uin, ts)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("X-Launcher-Signature", sigHeader)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	tok := rr.Header().Get("X-Set-Token")
	if tok == "" {
		t.Fatal("missing X-Set-Token")
	}

	// Parse and validate the returned token.
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tok, claims, func(t *jwt.Token) (any, error) {
		return testSecret, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("returned token invalid: %v", err)
	}
	if claims.UIN != uin {
		t.Fatalf("token uin = %d, want %d", claims.UIN, uin)
	}
}

func TestSituationB_ExpiredTimestamp(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 1
	ts := time.Now().Unix() - 400 // 400 s in the past
	sigHeader := buildSignatureHeader(testPrivKey, uin, ts)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("X-Launcher-Signature", sigHeader)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired timestamp, got %d", rr.Code)
	}
}

func TestSituationB_FutureTimestamp(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 2
	ts := time.Now().Unix() + 400 // 400 s in the future
	sigHeader := buildSignatureHeader(testPrivKey, uin, ts)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("X-Launcher-Signature", sigHeader)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for future timestamp, got %d", rr.Code)
	}
}

func TestSituationB_UINMismatch(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const sigUIN uint64 = 100
	const bodyUINVal uint64 = 200
	ts := time.Now().Unix()
	sigHeader := buildSignatureHeader(testPrivKey, sigUIN, ts)

	req := httptest.NewRequest(http.MethodPost, "/", body(bodyUINVal))
	req.Header.Set("X-Launcher-Signature", sigHeader)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for uin mismatch, got %d", rr.Code)
	}
}

func TestSituationB_BadSignature(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 3
	ts := time.Now().Unix()

	// Build payload with a random (wrong) signature.
	payload := make([]byte, PayloadSize)
	binary.BigEndian.PutUint64(payload[0:8], uin)
	binary.BigEndian.PutUint64(payload[8:16], uint64(ts))
	if _, err := rand.Read(payload[16:80]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	sigHeader := base64.StdEncoding.EncodeToString(payload)

	req := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req.Header.Set("X-Launcher-Signature", sigHeader)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d", rr.Code)
	}
}

func TestSituationB_ReplayRejected(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 77
	ts := time.Now().Unix()
	sigHeader := buildSignatureHeader(testPrivKey, uin, ts)

	// First request: should succeed.
	req1 := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req1.Header.Set("X-Launcher-Signature", sigHeader)
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d: %s", rr1.Code, rr1.Body.String())
	}

	// Second request with identical header: should be rejected as replay.
	req2 := httptest.NewRequest(http.MethodPost, "/", body(uin))
	req2.Header.Set("X-Launcher-Signature", sigHeader)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("replay: expected 401, got %d", rr2.Code)
	}
	if !strings.Contains(rr2.Body.String(), "replayed") {
		t.Fatalf("expected 'replayed' in body, got: %s", rr2.Body.String())
	}
}

func TestSituationB_InvalidBase64(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", body(1))
	req.Header.Set("X-Launcher-Signature", "!!!not-base64!!!")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad base64, got %d", rr.Code)
	}
}

// ---- No auth headers --------------------------------------------------------

func TestNoAuthHeader(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	req := httptest.NewRequest(http.MethodPost, "/", body(1))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no auth headers, got %d", rr.Code)
	}
}

// ---- Body preservation ------------------------------------------------------

func TestBodyPreservedAfterRead(t *testing.T) {
	m := newMiddleware()

	const uin uint64 = 42
	tokenStr := buildBearerToken(uin, testSecret)

	var gotBody []byte
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = b
		w.WriteHeader(http.StatusOK)
	})

	bodyJSON, _ := json.Marshal(map[string]uint64{"uin": uin})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rr := httptest.NewRecorder()
	m.Handler(captureHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !bytes.Equal(gotBody, bodyJSON) {
		t.Fatalf("body was not preserved: got %s, want %s", gotBody, bodyJSON)
	}
}

// ---- Concurrency ------------------------------------------------------------

func TestConcurrentRequests(t *testing.T) {
	m := newMiddleware()
	h := m.Handler(okHandler)

	const uin uint64 = 999
	tokenStr := buildBearerToken(uin, testSecret)

	done := make(chan struct{}, 50)
	for i := 0; i < 50; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/", body(uin))
			req.Header.Set("Authorization", "Bearer "+tokenStr)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("concurrent request failed: %d", rr.Code)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}
