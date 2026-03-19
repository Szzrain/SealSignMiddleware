package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Raw YAML shape
// ---------------------------------------------------------------------------

type rawConfig struct {
	Server struct {
		Addr string `yaml:"addr"`
	} `yaml:"server"`

	Auth struct {
		JWTSecret        string `yaml:"jwt_secret"`
		PublicKeyHexFile string `yaml:"public_key_hex_file"`
	} `yaml:"auth"`

	Routes []struct {
		Prefix        string `yaml:"prefix"`
		Target        string `yaml:"target"`
		UpstreamToken string `yaml:"upstream_token"`
	} `yaml:"routes"`
}

// ---------------------------------------------------------------------------
// Parsed / strongly-typed config
// ---------------------------------------------------------------------------

// RouteRule maps a URL path prefix to an upstream target host.
type RouteRule struct {
	Prefix        string // e.g. "/api/v1/"
	Target        string // e.g. "https://httpbin.org"
	UpstreamToken string // Bearer token injected into upstream requests (never forwarded back)
}

// AppConfig holds the fully-parsed configuration used by the server.
type AppConfig struct {
	Addr      string            // HTTP listen address
	JWTSecret []byte            // HMAC-SHA256 secret for JWT
	PublicKey ed25519.PublicKey // Ed25519 verification key (may be nil)
	Routes    []RouteRule       // ordered list of prefix → target rules
}

// LoadConfig reads path, parses YAML and resolves the Ed25519 public key.
func LoadConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}

	cfg := &AppConfig{
		Addr:      raw.Server.Addr,
		JWTSecret: []byte(raw.Auth.JWTSecret),
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}

	// Load Ed25519 public key from hex file (optional).
	if raw.Auth.PublicKeyHexFile != "" {
		cfg.PublicKey, err = loadPublicKeyHex(raw.Auth.PublicKeyHexFile)
		if err != nil {
			return nil, err
		}
	}

	// Build route table.
	for _, r := range raw.Routes {
		if r.Prefix == "" || r.Target == "" {
			return nil, fmt.Errorf("config: route entry missing prefix or target")
		}
		cfg.Routes = append(cfg.Routes, RouteRule{
			Prefix:        r.Prefix,
			Target:        strings.TrimRight(r.Target, "/"),
			UpstreamToken: r.UpstreamToken,
		})
	}

	return cfg, nil
}

// loadPublicKeyHex reads a file containing the hex-encoded 32-byte Ed25519
// public key (whitespace is trimmed automatically).
func loadPublicKeyHex(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read public key file %s: %w", path, err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("config: decode public key hex: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("config: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(decoded))
	}
	return decoded, nil
}
