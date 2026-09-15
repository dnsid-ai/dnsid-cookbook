package validation

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

func MessageBody(value string) (string, error) {
	value = strings.Trim(value, "\r\n")
	if value == "" {
		return "", fmt.Errorf("body is required")
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("body must be valid UTF-8")
	}
	if len([]byte(value)) > board.MaxMessageBytes {
		return "", fmt.Errorf("body exceeds %d bytes", board.MaxMessageBytes)
	}
	return value, nil
}

func Nickname(value string) (string, string, error) {
	if value == "" {
		return "", "", fmt.Errorf("nickname is required")
	}
	if len(value) > board.MaxNicknameLength {
		return "", "", fmt.Errorf("nickname exceeds %d characters", board.MaxNicknameLength)
	}
	if strings.TrimSpace(value) != value {
		return "", "", fmt.Errorf("nickname must not have leading or trailing whitespace")
	}
	for i, ch := range value {
		if isNicknameAlphaNum(ch) || ch == '.' || ch == '_' || ch == '-' {
			if (i == 0 || i == len(value)-1) && !isNicknameAlphaNum(ch) {
				return "", "", fmt.Errorf("nickname must start and end with a letter or digit")
			}
			continue
		}
		return "", "", fmt.Errorf("nickname contains invalid character")
	}
	return value, strings.ToLower(value), nil
}

func isNicknameAlphaNum(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}
