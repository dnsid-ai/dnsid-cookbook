package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	APIEndpoint string
	Audience    string
	DNSIDServer string
	AgentDomain string
	DNSIDCLI    string
	OutputJSON  bool
}

type configFile struct {
	Profiles       map[string]profile `json:"profiles"`
	CurrentProfile string             `json:"current_profile"`
}

type profile struct {
	APIEndpoint string `json:"api_endpoint"`
	Audience    string `json:"audience"`
	DNSIDServer string `json:"dnsid_server"`
	AgentDomain string `json:"agent_domain"`
	DNSIDCLI    string `json:"dnsid_cli"`
}

func loadConfig(profileName string, outputJSON bool) (Config, error) {
	cfg := Config{
		DNSIDServer: "https://api.dnsid.dev",
		DNSIDCLI:    defaultDNSIDCLI(),
		OutputJSON:  outputJSON || os.Getenv("DNSID_BOARD_OUTPUT") == "json",
	}
	file, err := readConfigFile()
	if err != nil {
		return Config{}, err
	}
	if profileName == "" {
		profileName = file.CurrentProfile
	}
	if profileName != "" && file.Profiles != nil {
		if prof, ok := file.Profiles[profileName]; ok {
			cfg.APIEndpoint = prof.APIEndpoint
			cfg.Audience = prof.Audience
			cfg.DNSIDServer = valueOr(prof.DNSIDServer, cfg.DNSIDServer)
			cfg.AgentDomain = prof.AgentDomain
			cfg.DNSIDCLI = valueOr(prof.DNSIDCLI, cfg.DNSIDCLI)
		}
	}
	cfg.APIEndpoint = envOverride("DNSID_BOARD_API", cfg.APIEndpoint)
	cfg.Audience = envOverride("DNSID_BOARD_AUDIENCE", cfg.Audience)
	cfg.DNSIDServer = envOverride("DNSID_SERVER", cfg.DNSIDServer)
	cfg.AgentDomain = envOverride("DNSID_AGENT_DOMAIN", cfg.AgentDomain)
	cfg.DNSIDCLI = envOverride("DNSID_CLI", cfg.DNSIDCLI)
	return cfg, nil
}

func saveConfig(cfg Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file := configFile{
		CurrentProfile: "lab",
		Profiles: map[string]profile{
			"lab": {
				APIEndpoint: cfg.APIEndpoint,
				Audience:    cfg.Audience,
				DNSIDServer: cfg.DNSIDServer,
				AgentDomain: cfg.AgentDomain,
				DNSIDCLI:    cfg.DNSIDCLI,
			},
		},
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0600)
}

func readConfigFile() (configFile, error) {
	path, err := configPath()
	if err != nil {
		return configFile{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return configFile{}, nil
		}
		return configFile{}, err
	}
	var file configFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return configFile{}, err
	}
	return file, nil
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".dnsid-board", "config.json"), nil
}

func requireConfig(cfg Config) error {
	var missing []string
	if cfg.APIEndpoint == "" {
		missing = append(missing, "DNSID_BOARD_API")
	}
	if cfg.Audience == "" {
		missing = append(missing, "DNSID_BOARD_AUDIENCE")
	}
	if cfg.AgentDomain == "" {
		missing = append(missing, "DNSID_AGENT_DOMAIN")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing config: %s", strings.Join(missing, ", "))
	}
	return nil
}

func defaultDNSIDCLI() string {
	return "dnsid"
}

func envOverride(key string, current string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return current
}

func valueOr(value string, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
