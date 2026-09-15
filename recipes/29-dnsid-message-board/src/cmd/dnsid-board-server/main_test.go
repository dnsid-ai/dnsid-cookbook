package main

import (
	"testing"
)

func TestLoadServerConfigRequiresExplicitBackend(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "")
	t.Setenv("DDB_TABLE_NAME", "")
	t.Setenv("AVP_POLICY_STORE_ID", "")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected explicit BOARD_BACKEND requirement")
	}
	t.Setenv("BOARD_BACKEND", "local")
	cfg, err := loadServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Backend != "local" {
		t.Fatalf("backend = %q", cfg.Backend)
	}
}

func TestLoadServerConfigRejectsImplicitPartialAWSConfig(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "")
	t.Setenv("DDB_TABLE_NAME", "table")
	t.Setenv("AVP_POLICY_STORE_ID", "")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected backend requirement when AWS config is present")
	}
}

func TestLoadServerConfigRejectsLocalBackendWithAWSConfig(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "local")
	t.Setenv("DDB_TABLE_NAME", "table")
	t.Setenv("AVP_POLICY_STORE_ID", "")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected local backend to reject AWS config")
	}
}

func TestLoadServerConfigRejectsLocalBackendWithDynamoDBEndpoint(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "local")
	t.Setenv("DDB_ENDPOINT", "http://127.0.0.1:4566")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected local backend to reject DDB_ENDPOINT")
	}
}

func TestLoadServerConfigRejectsInvalidBackend(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "sqlite")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected invalid backend error")
	}
}

func TestLoadServerConfigAWSRequiresDynamoDBAndAVP(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "aws")
	t.Setenv("DNSID_ISSUER", "https://api.dnsid.dev")
	t.Setenv("DNSID_ENVIRONMENT", "lab")
	t.Setenv("BOARD_API_AUDIENCES", "urn:test")
	t.Setenv("DDB_TABLE_NAME", "table")
	t.Setenv("AVP_POLICY_STORE_ID", "")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected aws backend to require AVP_POLICY_STORE_ID")
	}
	t.Setenv("AVP_POLICY_STORE_ID", "policy-store")
	if _, err := loadServerConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadServerConfigAWSRequiresIssuerEnvironmentAudienceAndDynamoDB(t *testing.T) {
	clearServerConfigEnv(t)
	t.Setenv("BOARD_BACKEND", "aws")
	t.Setenv("DNSID_ISSUER", "")
	t.Setenv("DNSID_ENVIRONMENT", "")
	t.Setenv("BOARD_API_AUDIENCES", "")
	t.Setenv("DDB_TABLE_NAME", "")
	t.Setenv("AVP_POLICY_STORE_ID", "policy-store")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected aws backend to require issuer/environment/audience/ddb")
	}
}

func TestLoadServerConfigAWSRequiresHTTPSIssuer(t *testing.T) {
	clearServerConfigEnv(t)
	setValidAWSConfig(t)
	t.Setenv("DNSID_ISSUER", "http://api.dnsid.dev")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected aws backend to require HTTPS issuer")
	}
}

func TestLoadServerConfigAWSAllowsOnlyLocalDynamoDBEndpoint(t *testing.T) {
	clearServerConfigEnv(t)
	setValidAWSConfig(t)
	t.Setenv("DDB_ENDPOINT", "https://dynamodb.us-east-1.amazonaws.com")
	if _, err := loadServerConfig(); err == nil {
		t.Fatal("expected aws backend to reject non-local DDB_ENDPOINT")
	}
	t.Setenv("DDB_ENDPOINT", "http://127.0.0.1:4566")
	if _, err := loadServerConfig(); err != nil {
		t.Fatal(err)
	}
}

func setValidAWSConfig(t *testing.T) {
	t.Helper()
	t.Setenv("BOARD_BACKEND", "aws")
	t.Setenv("DNSID_ISSUER", "https://api.dnsid.dev")
	t.Setenv("DNSID_ENVIRONMENT", "lab")
	t.Setenv("BOARD_API_AUDIENCES", "urn:test")
	t.Setenv("DDB_TABLE_NAME", "table")
	t.Setenv("AVP_POLICY_STORE_ID", "policy-store")
}

func clearServerConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"ADDR",
		"BOARD_BACKEND",
		"DNSID_ISSUER",
		"DNSID_SERVER",
		"DNSID_ENVIRONMENT",
		"BOARD_API_AUDIENCES",
		"DDB_TABLE_NAME",
		"DDB_ENDPOINT",
		"AVP_POLICY_STORE_ID",
	} {
		t.Setenv(key, "")
	}
}
