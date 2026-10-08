// Command authgo-interop signs and verifies server-signed AAuth requests with
// auth-go (github.com/aauth-dev/auth-go, the Go AAuth module on aauth.dev), so
// the Python test suite can check this Supervision Server against an
// independent implementation in another language.
//
// It reads one JSON object on stdin and writes one JSON object on stdout:
//
//	sign:   {"issuer","dwk","kid","seed","method","url","headers","body"}
//	        -> {"headers": {...}}  (ServerSigner.SignRequest, jwks_uri scheme)
//	verify: {"issuer","dwk","kid","x","method","url","headers","body"}
//	        -> {"ok": true, "id": "..."} or {"ok": false, "error": "..."}
//	        (VerifyServerRequest with body coverage required, as at a PS or SS)
//
// seed and x are base64url (no padding) Ed25519 private seed and public key;
// body is base64url of the exact bytes, empty for none.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	aauth "github.com/aauth-dev/auth-go"
)

type input struct {
	Issuer  string            `json:"issuer"`
	DWK     string            `json:"dwk"`
	Kid     string            `json:"kid"`
	Seed    string            `json:"seed"`
	X       string            `json:"x"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// staticResolver returns one known key for one (issuer, dwk, kid), standing in
// for jwks_uri discovery, which needs the network.
type staticResolver struct {
	in  input
	pub ed25519.PublicKey
}

func (r staticResolver) ResolveKey(_ context.Context, iss, dwk, kid string, _ *aauth.JWK) (crypto.PublicKey, error) {
	if iss != r.in.Issuer || dwk != r.in.DWK || kid != r.in.Kid {
		return nil, fmt.Errorf("unknown key %s %s %s", iss, dwk, kid)
	}
	return r.pub, nil
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func request(in input) (*http.Request, error) {
	body, err := b64(in.Body)
	if err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(in.Method, in.URL, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func run(cmd string, in input) (any, error) {
	req, err := request(in)
	if err != nil {
		return nil, err
	}
	switch cmd {
	case "sign":
		seed, err := b64(in.Seed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("seed: want %d bytes base64url", ed25519.SeedSize)
		}
		signer := aauth.ServerSigner{Issuer: in.Issuer, DWK: in.DWK, Kid: in.Kid,
			Key: ed25519.NewKeyFromSeed(seed)}
		if err := signer.SignRequest(req); err != nil {
			return nil, err
		}
		out := map[string]string{}
		for k := range req.Header {
			out[strings.ToLower(k)] = req.Header.Get(k)
		}
		return map[string]any{"headers": out}, nil
	case "verify":
		x, err := b64(in.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("x: want %d bytes base64url", ed25519.PublicKeySize)
		}
		caller, err := aauth.VerifyServerRequest(context.Background(), req, aauth.VerifyServerOptions{
			Resolver:  staticResolver{in: in, pub: ed25519.PublicKey(x)},
			Signature: aauth.RequestVerifyOptions{RequireBodyCoverage: true},
		})
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		return map[string]any{"ok": true, "id": caller.ID}, nil
	}
	return nil, fmt.Errorf("unknown command %q (want sign or verify)", cmd)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: authgo-interop sign|verify < request.json")
		os.Exit(2)
	}
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "input:", err)
		os.Exit(2)
	}
	out, err := run(os.Args[1], in)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
}
