// mockclient is a command-line test tool for the SealSignMiddleware server.
//
// It exercises the full two-leg authentication flow:
//
//	Leg 1 – X-Launcher-Signature
//	  Builds uin(8B) | timestamp(8B) | ed25519-signature(64B), Base2048-encodes
//	  it, sends a POST to the target server, and reads the X-Set-Token header
//	  from the response.
//
//	Leg 2 – Bearer JWT
//	  Uses the token received in Leg 1 to call the same (or a different) path
//	  with Authorization: Bearer <token>.
//
// Usage:
//
//	go run ./mockclient [flags]
//
// Flags:
//
//	-server   base URL of the proxy server (default: http://localhost:8080)
//	-path     request path to call         (default: /get)
//	-uin      uint64 user identifier       (default: 12345678)
//	-privkey  hex file with 64-byte Ed25519 private key (default: keys/private.hex)
//	          If the file does not exist the client generates a fresh key pair,
//	          writes private.hex / public.hex into the same directory, and
//	          prints the public key so you can paste it into the server config.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Szzrain/SealSignMiddleware/middleware"
)

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

var (
	flagServer  = flag.String("server", "http://localhost:8080", "proxy server base URL")
	flagPath    = flag.String("path", "/api/sign/sec-sign", "request path")
	flagUIN     = flag.Uint64("uin", 12345678, "user identifier (uin)")
	flagPrivKey = flag.String("privkey", "keys/private.hex", "path to 64-byte Ed25519 private key hex file")
)

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[mockclient] ")

	// 1. Load (or generate) the Ed25519 private key.
	privKey := loadOrGeneratePrivKey(*flagPrivKey)

	uin := *flagUIN
	target := strings.TrimRight(*flagServer, "/") + *flagPath
	body := buildBody(uin)

	// -----------------------------------------------------------------------
	// Leg 1: X-Launcher-Signature
	// -----------------------------------------------------------------------
	log.Println("── Leg 1: X-Launcher-Signature ──────────────────────────────")
	sigHeader := buildSignatureHeader(privKey, uin)
	log.Printf("  UIN       : %d", uin)
	log.Printf("  Path      : %s", target)
	log.Printf("  Sig header: %.40s…", sigHeader)

	resp1, respBody1 := doRequest(target, sigHeader, "", body)
	token := resp1.Header.Get("X-Set-Token")
	log.Printf("  HTTP status : %s", resp1.Status)
	log.Printf("  X-Set-Token : %s", token)
	log.Printf("  Response body (first 512 B):\n%s", truncate(respBody1, 512))

	if token == "" {
		log.Fatal("Leg 1 failed: no X-Set-Token in response – check server logs")
	}

	// -----------------------------------------------------------------------
	// Leg 2: Bearer JWT
	// -----------------------------------------------------------------------
	log.Println("── Leg 2: Bearer JWT ─────────────────────────────────────────")
	resp2, respBody2 := doRequest(target, "", token, body)
	log.Printf("  HTTP status : %s", resp2.Status)
	log.Printf("  Response body (first 512 B):\n%s", truncate(respBody2, 512))

	// -----------------------------------------------------------------------
	// Leg 3: Replay attack (should be rejected with 401)
	// -----------------------------------------------------------------------
	log.Println("── Leg 3: replay of Leg-1 signature (expect 401) ────────────")
	resp3, respBody3 := doRequest(target, sigHeader, "", body)
	log.Printf("  HTTP status : %s", resp3.Status)
	log.Printf("  Response body: %s", strings.TrimSpace(string(respBody3)))

	// -----------------------------------------------------------------------
	// Leg 4: Expired / wrong JWT (should be rejected with 401)
	// -----------------------------------------------------------------------
	log.Println("── Leg 4: tampered JWT (expect 401) ──────────────────────────")
	resp4, respBody4 := doRequest(target, "", token+"X", body)
	log.Printf("  HTTP status : %s", resp4.Status)
	log.Printf("  Response body: %s", strings.TrimSpace(string(respBody4)))

	_ = resp2
	_ = respBody2
}

// ---------------------------------------------------------------------------
// Signature helpers
// ---------------------------------------------------------------------------

// buildSignatureHeader constructs the X-Launcher-Signature value:
//
//	payload = uin(8B big-endian) | timestamp(8B big-endian)
//	sig     = Ed25519Sign(privKey, payload)
//	header  = Base2048Encode(uin | timestamp | sig)
func buildSignatureHeader(privKey ed25519.PrivateKey, uin uint64) string {
	var msg [16]byte
	binary.BigEndian.PutUint64(msg[0:8], uin)
	binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().Unix()))

	sig := ed25519.Sign(privKey, msg[:])

	var payload [80]byte
	copy(payload[0:16], msg[:])
	copy(payload[16:80], sig)

	return middleware.Base2048Encode(payload[:])
}

type bodyCompat struct {
	UIN     uint64 `json:"uin"`
	Command string `json:"command"`
	Seq     uint64 `json:"seq"`
	Body    string `json:"body"`
	Guid    string `json:"guid"`
	Qua     string `json:"qua"`
}

// buildBody returns a minimal JSON body containing the uin field.
func buildBody(uin uint64) []byte {
	b, _ := json.Marshal(bodyCompat{
		UIN:     uin,
		Command: "wtlogin.login",
		Seq:     1,
		Body:    "1122334411223344",
		Guid:    "e8581c1595667d1008c8fa47b6199127",
		Qua:     "V1_LNX_NQ_3.2.26_46494_GW_B",
	})
	return b
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

// doRequest sends a POST with the given body.
//
//	sigHeader – if non-empty, sets X-Launcher-Signature
//	jwtToken  – if non-empty, sets Authorization: Bearer <token>
func doRequest(url, sigHeader, jwtToken string, body []byte) (*http.Response, []byte) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if sigHeader != "" {
		req.Header.Set("X-Launcher-Signature", sigHeader)
	}
	if jwtToken != "" {
		req.Header.Set("Authorization", "Bearer "+jwtToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	return resp, respBody
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

// loadOrGeneratePrivKey loads the Ed25519 private key from hexFile.
// If the file does not exist it generates a new key pair, writes both files
// (private.hex, public.hex) next to hexFile, and logs the public key.
func loadOrGeneratePrivKey(hexFile string) ed25519.PrivateKey {
	raw, err := os.ReadFile(hexFile)
	if err == nil {
		decoded, err2 := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err2 != nil {
			log.Fatalf("decode private key: %v", err2)
		}
		if len(decoded) != ed25519.PrivateKeySize {
			log.Fatalf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(decoded))
		}
		log.Printf("loaded private key from %s", hexFile)
		return ed25519.PrivateKey(decoded)
	}

	// File not found – generate a fresh pair.
	log.Printf("key file %s not found, generating new Ed25519 key pair…", hexFile)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("generate key pair: %v", err)
	}

	dir := dirOf(hexFile)
	privPath := hexFile
	pubPath := dir + "public.hex"

	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		log.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		log.Fatalf("write public key: %v", err)
	}

	log.Printf("private key written to %s", privPath)
	log.Printf("public  key written to %s", pubPath)
	log.Printf("──────────────────────────────────────────────────────────────")
	log.Printf("  PASTE this into server/config.yaml → auth.public_key_hex_file:")
	log.Printf("  %s", hex.EncodeToString(pub))
	log.Printf("  (or point public_key_hex_file to %s)", pubPath)
	log.Printf("──────────────────────────────────────────────────────────────")

	return priv
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + fmt.Sprintf("\n… (%d bytes total)", len(b))
}

// dirOf returns the directory component of path, always ending with "/".
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i+1]
		}
	}
	return "./"
}
