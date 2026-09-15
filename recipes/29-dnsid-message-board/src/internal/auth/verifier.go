package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/oidc"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/validation"
)

var ErrUnauthorized = errors.New("unauthorized")

type Verifier interface {
	VerifyBearer(ctx context.Context, token string) (board.Identity, error)
}

type OIDCVerifier struct {
	profile     *oidc.Profile
	issuer      string
	audiences   []string
	environment string
}

type OIDCVerifierConfig struct {
	Issuer         string
	Audiences      []string
	Environment    string
	Resolver       dnsid.IdentityResolver
	UnsafeLoopback bool
}

func NewOIDCVerifier(config OIDCVerifierConfig) (*OIDCVerifier, error) {
	issuer := strings.TrimRight(strings.TrimSpace(config.Issuer), "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	var audiences []string
	for _, audience := range config.Audiences {
		if audience = strings.TrimSpace(audience); audience != "" {
			audiences = append(audiences, audience)
		}
	}
	if len(audiences) == 0 {
		return nil, fmt.Errorf("at least one audience is required")
	}
	if config.Resolver == nil {
		return nil, fmt.Errorf("DNSid resolver is required")
	}

	profile := oidc.New(config.Resolver, "", nil, oidc.Config{
		AllowedIssuers:          []string{issuer},
		AllowHTTPLoopbackIssuer: config.UnsafeLoopback,
	})
	return &OIDCVerifier{profile: profile, issuer: issuer, audiences: audiences, environment: config.Environment}, nil
}

func (v *OIDCVerifier) VerifyBearer(ctx context.Context, token string) (board.Identity, error) {
	var verified *oidc.VerifiedOIDCSubject
	var verifyErr error
	for _, audience := range v.audiences {
		result, err := v.profile.VerifyOIDCToken(ctx, token, oidc.VerifyOIDCTokenOptions{
			Issuer:   v.issuer,
			Audience: audience,
		})
		if err == nil {
			verified = result
			break
		}
		verifyErr = err
	}
	if verified == nil || verified.VerifiedDomain == nil {
		return board.Identity{}, fmt.Errorf("%w: %v", ErrUnauthorized, verifyErr)
	}

	jti, _ := verified.Claims["jti"].(string)
	exp, ok := verified.Claims["exp"].(float64)
	environment, _ := verified.Claims["environment"].(string)
	if jti == "" || !ok || v.environment != "" && environment != v.environment {
		return board.Identity{}, ErrUnauthorized
	}
	agent := verified.VerifiedDomain.Domain()
	if fqdn, _ := verified.Claims["fqdn"].(string); fqdn != "" {
		canonical, err := validation.CanonicalDNSName(fqdn)
		if err != nil || canonical != agent {
			return board.Identity{}, ErrUnauthorized
		}
	}
	tokenHash := sha256.Sum256([]byte(verified.Issuer + ":" + jti))
	return board.Identity{
		Agent:        agent,
		Issuer:       verified.Issuer,
		Audience:     []string{verified.Audience},
		Environment:  environment,
		TokenJTIHash: "sha256:" + base64.RawURLEncoding.EncodeToString(tokenHash[:]),
		ExpiresAt:    int64(exp),
	}, nil
}

// UnsafeTokenExpiry is display-only. Authentication uses oidc.VerifyOIDCToken.
func UnsafeTokenExpiry(token string) (int64, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, fmt.Errorf("malformed jwt")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, err
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil || claims.Exp == 0 {
		return 0, fmt.Errorf("missing exp")
	}
	return claims.Exp, nil
}
