package validation

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func NormalizeRoomID(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("room_id is required")
	}
	if strings.Trim(value, " \t\r\n") != value {
		return "", fmt.Errorf("room_id must not have leading or trailing ASCII whitespace")
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("room_id must be valid UTF-8")
	}
	normalized := norm.NFC.String(value)
	if normalized != value {
		return "", fmt.Errorf("room_id must already be NFC normalized")
	}
	if utf8.RuneCountInString(normalized) > 128 || len([]byte(normalized)) > 512 {
		return "", fmt.Errorf("room_id is too long")
	}
	for _, ch := range normalized {
		if ch < 0x20 || ch == 0x7f {
			return "", fmt.Errorf("room_id must not contain control characters")
		}
	}
	return normalized, nil
}

func RoomKey(roomID string) (string, error) {
	normalized, err := NormalizeRoomID(roomID)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(normalized)), nil
}
