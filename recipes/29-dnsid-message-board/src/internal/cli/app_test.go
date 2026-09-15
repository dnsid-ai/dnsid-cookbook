package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCLIMintsTokenForEachCommand(t *testing.T) {
	countFile, dnsidPath := fakeDNSID(t)
	var seen atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer auth")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"agent":             "agent.example.com",
			"issuer":            "https://api.dnsid.dev",
			"audience":          "urn:test",
			"environment":       "lab",
			"token_jti_present": true,
		})
	}))
	defer server.Close()
	setCLIEnv(t, server.URL, dnsidPath)

	for i := 0; i < 2; i++ {
		var out, errOut bytes.Buffer
		if code := Main([]string{"whoami"}, &out, &errOut); code != 0 {
			t.Fatalf("whoami failed: code=%d stderr=%s", code, errOut.String())
		}
		if strings.Contains(out.String(), "Bearer ") {
			t.Fatalf("output leaked token: %s", out.String())
		}
	}
	if got := readCount(t, countFile); got != 2 {
		t.Fatalf("expected two token mints, got %d", got)
	}
	if seen.Load() != 2 {
		t.Fatalf("expected two HTTP calls, got %d", seen.Load())
	}
}

func TestCLIRetriesOnceWithFreshTokenAfterUnauthorized(t *testing.T) {
	countFile, dnsidPath := fakeDNSID(t)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": map[string]any{"code": "unauthorized", "message": "expired"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                true,
			"agent":             "agent.example.com",
			"issuer":            "https://api.dnsid.dev",
			"audience":          "urn:test",
			"environment":       "lab",
			"token_jti_present": true,
		})
	}))
	defer server.Close()
	setCLIEnv(t, server.URL, dnsidPath)

	var out, errOut bytes.Buffer
	if code := Main([]string{"whoami"}, &out, &errOut); code != 0 {
		t.Fatalf("whoami failed: code=%d stderr=%s", code, errOut.String())
	}
	if got := readCount(t, countFile); got != 2 {
		t.Fatalf("expected retry to mint second token, got %d", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected one retry, got %d calls", calls.Load())
	}
}

func TestCLIWorkflowUsesDirectHTTPAndSupportsDelimiterRoomIDs(t *testing.T) {
	countFile, dnsidPath := fakeDNSID(t)
	calls := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing bearer auth")
		}
		key := r.Method + " " + r.URL.EscapedPath()
		calls[key]++
		w.Header().Set("Content-Type", "application/json")
		switch key {
		case "POST /v1/rooms":
			var body struct {
				RoomID string `json:"room_id"`
				Name   string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode room body: %v", err)
			}
			if body.RoomID != "--dash-room" || body.Name != "Dash Room" {
				t.Errorf("room create body = %+v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "room": map[string]any{"room_id": body.RoomID, "name": body.Name, "owner": "agent.example.com"}})
		case "POST /v1/rooms/room%2Fpath/messages":
			if r.Header.Get("Idempotency-Key") != "idem-1" {
				t.Errorf("idempotency header = %q", r.Header.Get("Idempotency-Key"))
			}
			var body struct {
				Body string `json:"body"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode post body: %v", err)
			}
			if body.Body != "hello" {
				t.Errorf("post body = %+v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": map[string]any{"message_id": "msg_1"}})
		case "GET /v1/rooms/room%2Fpath/messages":
			if calls[key] == 1 {
				if r.URL.Query().Get("limit") != "7" || r.URL.Query().Has("wait") {
					t.Errorf("read query = %s", r.URL.RawQuery)
				}
			} else if calls[key] == 2 {
				if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("wait") != "0" {
					t.Errorf("watch query = %s", r.URL.RawQuery)
				}
			} else {
				if r.URL.Query().Get("after") != "msg_01" {
					t.Errorf("after query = %s", r.URL.RawQuery)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "messages": []any{}})
		case "PUT /v1/rooms/room%2Fpath/nickname":
			var body struct {
				Nickname string `json:"nickname"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode nickname body: %v", err)
			}
			if body.Nickname != "wolfgang" {
				t.Errorf("nickname body = %q", body.Nickname)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "profile": map[string]any{"nickname": body.Nickname}})
		case "PUT /v1/rooms/room%2Fpath/allowlist/future.example.com":
			var body struct {
				Role string `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode allowlist body: %v", err)
			}
			if body.Role != "reader" {
				t.Errorf("allowlist role = %q", body.Role)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "created": true, "entry": map[string]any{"agent": "future.example.com", "role": body.Role}})
		default:
			t.Errorf("unexpected request: %s rawQuery=%s", key, r.URL.RawQuery)
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
		}
	}))
	defer server.Close()
	setCLIEnv(t, server.URL, dnsidPath)

	commands := [][]string{
		{"--json", "room", "create", "--name", "Dash Room", "--", "--dash-room"},
		{"--json", "post", "room/path", "--body", "hello", "--idempotency-key", "idem-1"},
		{"--json", "read", "room/path", "--limit", "7"},
		{"--json", "watch", "room/path", "--limit", "2", "--wait", "0"},
		{"--json", "read", "room/path", "--after", "msg_01"},
		{"--json", "nickname", "set", "room/path", "--nickname", "wolfgang"},
		{"--json", "allowlist", "grant", "room/path", "--agent", "future.example.com", "--role", "reader"},
	}
	for _, command := range commands {
		var out, errOut bytes.Buffer
		if code := Main(command, &out, &errOut); code != 0 {
			t.Fatalf("%v failed: code=%d stderr=%s", command, code, errOut.String())
		}
	}
	if got := readCount(t, countFile); got != len(commands) {
		t.Fatalf("expected one token mint per command, got %d want %d", got, len(commands))
	}
	for _, expected := range []struct {
		key  string
		want int
	}{
		{"POST /v1/rooms", 1},
		{"POST /v1/rooms/room%2Fpath/messages", 1},
		{"GET /v1/rooms/room%2Fpath/messages", 3},
		{"PUT /v1/rooms/room%2Fpath/nickname", 1},
		{"PUT /v1/rooms/room%2Fpath/allowlist/future.example.com", 1},
	} {
		if calls[expected.key] != expected.want {
			t.Fatalf("%s calls = %d, want %d", expected.key, calls[expected.key], expected.want)
		}
	}
}

func TestCLIPreservesDashPrefixedCommandFlagValues(t *testing.T) {
	_, dnsidPath := fakeDNSID(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.EscapedPath() != "/v1/rooms/room%2Fpath/messages" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.EscapedPath())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Idempotency-Key") != "--profile" {
			t.Errorf("idempotency header = %q, want --profile", r.Header.Get("Idempotency-Key"))
		}
		var body struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode post body: %v", err)
		}
		if body.Body != "--json" {
			t.Errorf("post body = %q, want --json", body.Body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "message": map[string]any{"message_id": "msg_1"}})
	}))
	defer server.Close()
	setCLIEnv(t, server.URL, dnsidPath)

	var out, errOut bytes.Buffer
	code := Main([]string{"--json", "post", "room/path", "--body", "--json", "--idempotency-key", "--profile"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("post failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestParseCommandFlagsAllowsFlagValuesStartingWithDash(t *testing.T) {
	fs := flag.NewFlagSet("post", flag.ContinueOnError)
	body := fs.String("body", "", "")
	idempotencyKey := fs.String("idempotency-key", "", "")

	positionals, err := parseCommandFlags(fs, []string{"room/path", "--body", "--hello", "--idempotency-key", "--idem"})
	if err != nil {
		t.Fatal(err)
	}
	if *body != "--hello" {
		t.Fatalf("body = %q, want --hello", *body)
	}
	if *idempotencyKey != "--idem" {
		t.Fatalf("idempotency key = %q, want --idem", *idempotencyKey)
	}
	if len(positionals) != 1 || positionals[0] != "room/path" {
		t.Fatalf("positionals = %v, want [room/path]", positionals)
	}
}

func fakeDNSID(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	countFile := filepath.Join(dir, "count")
	token := fakeJWT(time.Now().Add(time.Hour).Unix())
	path := filepath.Join(dir, "dnsid")
	script := fmt.Sprintf(`#!/bin/sh
n=$(cat "$DNSID_FAKE_COUNT" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$DNSID_FAKE_COUNT"
echo %q
`, token)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DNSID_FAKE_COUNT", countFile)
	return countFile, path
}

func fakeJWT(exp int64) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256"})
	payload, _ := json.Marshal(map[string]any{"exp": exp})
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func setCLIEnv(t *testing.T, api string, dnsidPath string) {
	t.Helper()
	t.Setenv("DNSID_BOARD_API", api)
	t.Setenv("DNSID_BOARD_AUDIENCE", "urn:test")
	t.Setenv("DNSID_SERVER", "https://api.dnsid.dev")
	t.Setenv("DNSID_AGENT_DOMAIN", "agent.example.com")
	t.Setenv("DNSID_CLI", dnsidPath)
}

func readCount(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if _, err := fmt.Sscanf(string(raw), "%d", &count); err != nil {
		t.Fatal(err)
	}
	return count
}
