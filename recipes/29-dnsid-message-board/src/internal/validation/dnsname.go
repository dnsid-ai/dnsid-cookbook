package validation

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

func CanonicalDNSName(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("dns name is required")
	}
	ascii, err := idna.Lookup.ToASCII(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid dns name: %w", err)
	}
	ascii = strings.ToLower(ascii)
	ascii = strings.TrimSuffix(ascii, ".")
	if ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid dns name length")
	}
	if strings.Contains(ascii, "*") || strings.Contains(ascii, "_") {
		return "", fmt.Errorf("dns name must not contain wildcards or underscores")
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("dns name must be fully qualified")
	}
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("dns name contains an empty label")
		}
		if len(label) > 63 {
			return "", fmt.Errorf("dns label exceeds 63 octets")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("dns label must not start or end with hyphen")
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return "", fmt.Errorf("dns label contains invalid character")
		}
	}
	roundTrip, err := idna.Lookup.ToASCII(ascii)
	if err != nil {
		return "", fmt.Errorf("invalid dns name round trip: %w", err)
	}
	if strings.ToLower(strings.TrimSuffix(roundTrip, ".")) != ascii {
		return "", fmt.Errorf("dns name is not stable after canonicalization")
	}
	return ascii, nil
}
