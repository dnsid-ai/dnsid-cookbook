package localregistry

import "testing"

func TestSecondLevelLocalURLs(t *testing.T) {
	fetcher := &localRegistryFetcher{suffix: "test"}
	for _, tc := range []struct {
		url, allowed    string
		boundary, valid bool
	}{
		{"https://writer.test/.well-known/jwks.json", "writer.test", false, true},
		{"https://dnsid.writer.test/.well-known/dnsid-ek.json", "writer.test", true, true},
		{"https://registry.test/dnsid-policy", "", false, true},
		{"https://outsider.test/.well-known/jwks.json", "writer.test", false, false},
		{"https://writer.test.evil.example/jwks", "", false, false},
		{"https://eviltest/jwks", "", false, false},
	} {
		if err := fetcher.validateURL(tc.url, tc.allowed, tc.boundary); (err == nil) != tc.valid {
			t.Errorf("validateURL(%q): %v, want valid=%v", tc.url, err, tc.valid)
		}
	}
}
