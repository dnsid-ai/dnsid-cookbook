package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigReturnsMalformedConfigError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	configDir := filepath.Join(home, ".dnsid-board")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), []byte("{not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig("", false); err == nil {
		t.Fatal("expected malformed config error")
	}
}
