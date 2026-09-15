package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	dnsid "github.com/dnsid-ai/dnsid-go"
	"github.com/dnsid-ai/dnsid-go/log/c2sptlog"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/auth"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/authorization"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/httpapi"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/store"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/testnet"
)

func main() {
	config, err := loadServerConfig()
	if err != nil {
		log.Fatalf("configure server: %v", err)
	}

	ctx := context.Background()
	resolver, unsafeLoopback, err := identityResolver(ctx, config.Backend)
	if err != nil {
		log.Fatalf("configure DNSid resolver: %v", err)
	}
	verifier, err := auth.NewOIDCVerifier(auth.OIDCVerifierConfig{
		Issuer:         config.Issuer,
		Audiences:      config.Audiences,
		Environment:    config.Environment,
		Resolver:       resolver,
		UnsafeLoopback: unsafeLoopback,
	})
	if err != nil {
		log.Fatalf("configure verifier: %v", err)
	}
	boardStore, boardAuthorizer, err := dependencies(ctx, config)
	if err != nil {
		log.Fatalf("configure dependencies: %v", err)
	}
	app := httpapi.New(boardStore, verifier, boardAuthorizer)
	server := &http.Server{
		Addr:              config.Addr,
		Handler:           app,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("dnsid-board-server listening on %s backend=%s", config.Addr, config.Backend)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type serverConfig struct {
	Addr         string
	Backend      string
	Issuer       string
	Environment  string
	Audiences    []string
	DDBTableName string
	DDBEndpoint  string
	AVPPolicyID  string
}

func loadServerConfig() (serverConfig, error) {
	backend := strings.TrimSpace(os.Getenv("BOARD_BACKEND"))
	ddbTableName := strings.TrimSpace(os.Getenv("DDB_TABLE_NAME"))
	avpPolicyID := strings.TrimSpace(os.Getenv("AVP_POLICY_STORE_ID"))
	if backend == "" {
		return serverConfig{}, fmt.Errorf("BOARD_BACKEND must be set to local or aws")
	}
	cfg := serverConfig{
		Addr:         env("ADDR", ":8080"),
		Backend:      backend,
		DDBTableName: ddbTableName,
		DDBEndpoint:  strings.TrimSpace(os.Getenv("DDB_ENDPOINT")),
		AVPPolicyID:  avpPolicyID,
	}
	switch backend {
	case "local":
		if ddbTableName != "" || avpPolicyID != "" || cfg.DDBEndpoint != "" {
			return serverConfig{}, fmt.Errorf("local backend does not accept DDB_TABLE_NAME, DDB_ENDPOINT, or AVP_POLICY_STORE_ID")
		}
		cfg.Issuer = env("DNSID_ISSUER", os.Getenv("DNSID_SERVER"))
		cfg.Environment = strings.TrimSpace(os.Getenv("DNSID_ENVIRONMENT"))
		cfg.Audiences = splitCSV(env("BOARD_API_AUDIENCES", "urn:dnsid-message-board:local"))
	case "aws":
		cfg.Issuer = strings.TrimSpace(os.Getenv("DNSID_ISSUER"))
		cfg.Environment = strings.TrimSpace(os.Getenv("DNSID_ENVIRONMENT"))
		cfg.Audiences = splitCSV(os.Getenv("BOARD_API_AUDIENCES"))
		var missing []string
		if cfg.Issuer == "" {
			missing = append(missing, "DNSID_ISSUER")
		}
		if cfg.Environment == "" {
			missing = append(missing, "DNSID_ENVIRONMENT")
		}
		if len(cfg.Audiences) == 0 {
			missing = append(missing, "BOARD_API_AUDIENCES")
		}
		if cfg.DDBTableName == "" {
			missing = append(missing, "DDB_TABLE_NAME")
		}
		if cfg.AVPPolicyID == "" {
			missing = append(missing, "AVP_POLICY_STORE_ID")
		}
		if len(missing) > 0 {
			return serverConfig{}, fmt.Errorf("aws backend missing required config: %s", strings.Join(missing, ", "))
		}
		if err := requireHTTPSIssuer(cfg.Issuer); err != nil {
			return serverConfig{}, err
		}
		if cfg.DDBEndpoint != "" {
			if err := requireLocalDDBEndpoint(cfg.DDBEndpoint); err != nil {
				return serverConfig{}, err
			}
		}
	default:
		return serverConfig{}, fmt.Errorf("BOARD_BACKEND must be local or aws")
	}
	return cfg, nil
}

func identityResolver(ctx context.Context, backend string) (dnsid.IdentityResolver, bool, error) {
	if backend == "local" {
		identity, err := testnet.LoadIdentity(ctx)
		return identity, true, err
	}
	policyURL := strings.TrimSpace(os.Getenv("DNSID_LOG_POLICY_URL"))
	if policyURL == "" {
		return nil, false, fmt.Errorf("DNSID_LOG_POLICY_URL is required")
	}
	logs, err := c2sptlog.NewVerificationRegistry(ctx, c2sptlog.VerificationRegistryConfig{PolicyURL: policyURL})
	if err != nil {
		return nil, false, fmt.Errorf("configure lifecycle log: %w", err)
	}
	resolver, err := dnsid.NewVerifier(dnsid.WithLogRegistry(logs))
	return resolver, false, err
}

func dependencies(ctx context.Context, serverConfig serverConfig) (store.Store, authorization.Authorizer, error) {
	if serverConfig.Backend == "local" {
		return store.NewMemoryStore(), authorization.NewLocalAuthorizer(), nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, nil, fmt.Errorf("aws backend requires AWS region configuration")
	}
	boardStore := store.NewDynamoDBStore(dynamodb.NewFromConfig(cfg, func(options *dynamodb.Options) {
		if serverConfig.DDBEndpoint != "" {
			options.BaseEndpoint = aws.String(serverConfig.DDBEndpoint)
		}
	}), serverConfig.DDBTableName)
	boardAuthorizer := authorization.NewAVPAuthorizer(verifiedpermissions.NewFromConfig(cfg), serverConfig.AVPPolicyID)
	return boardStore, boardAuthorizer, nil
}

func env(key string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func splitCSV(value string) []string {
	var values []string
	for _, part := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func requireHTTPSIssuer(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("aws backend requires DNSID_ISSUER to be an https URL")
	}
	return nil
}

func requireLocalDDBEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("DDB_ENDPOINT must be a URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err == nil && addr.IsLoopback() {
		return nil
	}
	return fmt.Errorf("DDB_ENDPOINT is only allowed for local emulator endpoints")
}
