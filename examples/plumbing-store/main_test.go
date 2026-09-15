package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyTokenAcceptsValidDemoToken(t *testing.T) {
	setupVerifierTest(t, nil)

	token, err := signQuoteJWT("Q-TEST", "Ada Lovelace", 125)
	if err != nil {
		t.Fatalf("signQuoteJWT: %v", err)
	}

	result := verifyToken(context.Background(), token)
	if !result.Valid {
		t.Fatalf("expected valid token, got error %q with steps %v", result.Error, result.Steps)
	}
}

func TestVerifyTokenRejectsMalformedSignedTokens(t *testing.T) {
	tests := []struct {
		name         string
		mutateHeader func(map[string]any)
		mutateClaims func(map[string]any)
		wantError    string
	}{
		{
			name: "missing kid",
			mutateHeader: func(header map[string]any) {
				delete(header, "kid")
			},
			wantError: "Missing kid header",
		},
		{
			name: "mismatched kid",
			mutateHeader: func(header map[string]any) {
				header["kid"] = "different-key"
			},
			wantError: "No JWKS key matched kid=different-key",
		},
		{
			name: "missing exp",
			mutateClaims: func(claims map[string]any) {
				delete(claims, "exp")
			},
			wantError: "Missing exp claim",
		},
		{
			name: "non-numeric exp",
			mutateClaims: func(claims map[string]any) {
				claims["exp"] = "tomorrow"
			},
			wantError: "exp claim must be numeric",
		},
		{
			name: "unexpected alg",
			mutateHeader: func(header map[string]any) {
				header["alg"] = "HS256"
			},
			wantError: `Unsupported alg "HS256": expected EdDSA`,
		},
		{
			name: "missing alg",
			mutateHeader: func(header map[string]any) {
				delete(header, "alg")
			},
			wantError: "Missing alg header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupVerifierTest(t, nil)

			header := validTestHeader()
			claims := validTestClaims()
			if tt.mutateHeader != nil {
				tt.mutateHeader(header)
			}
			if tt.mutateClaims != nil {
				tt.mutateClaims(claims)
			}

			result := verifyToken(context.Background(), signTestToken(t, header, claims))
			requireInvalid(t, result, tt.wantError)
		})
	}
}

func TestVerifyTokenRejectsJWKMetadataMismatch(t *testing.T) {
	tests := []struct {
		name      string
		mutateJWK func(map[string]any)
		wantError string
	}{
		{
			name: "wrong kty",
			mutateJWK: func(jwk map[string]any) {
				jwk["kty"] = "EC"
			},
			wantError: "expected OKP",
		},
		{
			name: "wrong crv",
			mutateJWK: func(jwk map[string]any) {
				jwk["crv"] = "P-256"
			},
			wantError: "expected Ed25519",
		},
		{
			name: "wrong alg",
			mutateJWK: func(jwk map[string]any) {
				jwk["alg"] = "ES256"
			},
			wantError: "expected EdDSA",
		},
		{
			name: "wrong use",
			mutateJWK: func(jwk map[string]any) {
				jwk["use"] = "enc"
			},
			wantError: "expected sig",
		},
		{
			name: "malformed use",
			mutateJWK: func(jwk map[string]any) {
				jwk["use"] = 42
			},
			wantError: "expected sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupVerifierTest(t, tt.mutateJWK)

			token, err := signQuoteJWT("Q-TEST", "Ada Lovelace", 125)
			if err != nil {
				t.Fatalf("signQuoteJWT: %v", err)
			}

			result := verifyToken(context.Background(), token)
			requireInvalid(t, result, tt.wantError)
		})
	}
}

func setupVerifierTest(t *testing.T, mutateJWK func(map[string]any)) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kid := jwkThumbprint(pub)
	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
		"kid": kid,
		"use": "sig",
		"alg": "EdDSA",
	}
	oldDNS := mockDNS[shopFQDN]
	oldPub, oldPriv, oldKeyID := pubKey, privKey, keyID

	pubKey, privKey, keyID = pub, priv, kid

	var handler http.Handler = http.HandlerFunc(handleJWKS)
	if mutateJWK != nil {
		mutateJWK(jwk)
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{jwk},
			})
		})
	}
	server := httptest.NewServer(handler)
	mockDNS[shopFQDN] = server.URL

	t.Cleanup(func() {
		server.Close()
		mockDNS[shopFQDN] = oldDNS
		pubKey, privKey, keyID = oldPub, oldPriv, oldKeyID
	})
}

func validTestHeader() map[string]any {
	return map[string]any{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": keyID,
	}
}

func validTestClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":      shopFQDN,
		"sub":      "quote:Q-TEST",
		"aud":      "customer",
		"iat":      now.Unix(),
		"exp":      now.Add(time.Hour).Unix(),
		"quote_id": "Q-TEST",
		"customer": "Ada Lovelace",
		"amount":   125,
	}
}

func signTestToken(t *testing.T, header, claims map[string]any) string {
	t.Helper()

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	h64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	p64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	input := h64 + "." + p64
	sig := ed25519.Sign(privKey, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func requireInvalid(t *testing.T, result verifyResult, wantError string) {
	t.Helper()

	if result.Valid {
		t.Fatalf("expected invalid token, got valid result with steps %v", result.Steps)
	}
	if !strings.Contains(result.Error, wantError) {
		t.Fatalf("expected error containing %q, got %q with steps %v", wantError, result.Error, result.Steps)
	}
}
