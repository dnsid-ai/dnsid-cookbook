package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/auth"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

func Main(args []string, stdout io.Writer, stderr io.Writer) int {
	app := app{stdout: stdout, stderr: stderr, httpClient: &http.Client{Timeout: time.Duration(board.MaxWatchSeconds+10) * time.Second}}
	if err := app.run(args); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type app struct {
	stdout     io.Writer
	stderr     io.Writer
	httpClient *http.Client
}

func (a app) run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dnsid-board <command>")
	}
	profileName, outputJSON, args := parseGlobal(args)
	if len(args) == 0 {
		return errors.New("usage: dnsid-board <command>")
	}
	if args[0] == "config" {
		return a.configCommand(args[1:])
	}
	cfg, err := loadConfig(profileName, outputJSON)
	if err != nil {
		return err
	}
	if err := requireConfig(cfg); err != nil {
		return err
	}
	switch args[0] {
	case "whoami":
		return a.whoami(cfg)
	case "room":
		return a.roomCommand(cfg, args[1:])
	case "post":
		return a.post(cfg, args[1:])
	case "read":
		return a.read(cfg, args[1:], false)
	case "watch":
		return a.read(cfg, args[1:], true)
	case "allowlist":
		return a.allowlistCommand(cfg, args[1:])
	case "nickname":
		return a.nicknameCommand(cfg, args[1:])
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func parseGlobal(args []string) (string, bool, []string) {
	var profile string
	outputJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			outputJSON = true
		case "--profile":
			if i+1 < len(args) {
				profile = args[i+1]
				i++
			}
		default:
			return profile, outputJSON, args[i:]
		}
	}
	return profile, outputJSON, nil
}

func (a app) configCommand(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("usage: dnsid-board config set --api <url> --audience <aud> --dnsid-server <url> --agent <fqdn>")
	}
	fs := flag.NewFlagSet("config set", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	api := fs.String("api", "", "")
	audience := fs.String("audience", "", "")
	server := fs.String("dnsid-server", "https://api.dnsid.dev", "")
	agent := fs.String("agent", "", "")
	dnsidCLI := fs.String("dnsid-cli", defaultDNSIDCLI(), "")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg := Config{APIEndpoint: *api, Audience: *audience, DNSIDServer: *server, AgentDomain: *agent, DNSIDCLI: *dnsidCLI}
	if err := requireConfig(cfg); err != nil {
		return err
	}
	if err := saveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "config: saved")
	return nil
}

func (a app) whoami(cfg Config) error {
	var response map[string]any
	exp, err := a.authRequest(context.Background(), cfg, http.MethodGet, "/v1/whoami", nil, nil, &response)
	if err != nil {
		return err
	}
	if cfg.OutputJSON {
		return printJSON(a.stdout, response)
	}
	fmt.Fprintf(a.stdout, "agent: %s\nissuer: %s\naudience: %s\nenvironment: %s\ntoken_expires_at: %s\n",
		response["agent"], response["issuer"], response["audience"], response["environment"], time.Unix(exp, 0).UTC().Format(time.RFC3339))
	return nil
}

func (a app) roomCommand(cfg Config, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dnsid-board room <create|list|get>")
	}
	switch args[0] {
	case "create":
		return a.roomCreate(cfg, args[1:])
	case "list":
		return a.roomList(cfg, args[1:])
	case "get":
		return a.roomGet(cfg, args[1:])
	default:
		return fmt.Errorf("unknown room command: %s", args[0])
	}
}

func (a app) roomCreate(cfg Config, args []string) error {
	fs := flag.NewFlagSet("room create", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	name := fs.String("name", "", "")
	description := fs.String("description", "", "")
	positionals, err := parseCommandFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: dnsid-board room create <room-id> [--name <name>]")
	}
	body := map[string]any{"room_id": positionals[0], "name": *name, "description": *description}
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodPost, "/v1/rooms", body, nil, &response); err != nil {
		return err
	}
	return a.printRoomCreate(cfg, response)
}

func (a app) roomList(cfg Config, args []string) error {
	fs := flag.NewFlagSet("room list", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	limit := fs.Int("limit", 0, "")
	cursor := fs.String("cursor", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	query := url.Values{}
	if *limit > 0 {
		query.Set("limit", fmt.Sprint(*limit))
	}
	if *cursor != "" {
		query.Set("cursor", *cursor)
	}
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodGet, withQuery("/v1/rooms", query), nil, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) roomGet(cfg Config, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: dnsid-board room get <room-id>")
	}
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodGet, "/v1/rooms/"+url.PathEscape(args[0]), nil, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) post(cfg Config, args []string) error {
	fs := flag.NewFlagSet("post", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	body := fs.String("body", "", "")
	idempotencyKey := fs.String("idempotency-key", "", "")
	positionals, err := parseCommandFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: dnsid-board post <room-id> --body <body>")
	}
	if *idempotencyKey == "" {
		*idempotencyKey = randomID()
	}
	headers := map[string]string{"Idempotency-Key": *idempotencyKey}
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodPost, "/v1/rooms/"+url.PathEscape(positionals[0])+"/messages", map[string]any{"body": *body}, headers, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) read(cfg Config, args []string, watch bool) error {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	limit := fs.Int("limit", 0, "")
	cursor := fs.String("cursor", "", "")
	after := fs.String("after", "", "")
	wait := fs.Int("wait", 25, "")
	positionals, err := parseCommandFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: dnsid-board read <room-id> [--limit <n>]")
	}
	query := url.Values{}
	if *limit > 0 {
		query.Set("limit", fmt.Sprint(*limit))
	}
	if *cursor != "" {
		query.Set("cursor", *cursor)
	}
	if *after != "" {
		query.Set("after", *after)
	}
	if watch {
		query.Set("wait", fmt.Sprint(*wait))
	}
	path := "/v1/rooms/" + url.PathEscape(positionals[0]) + "/messages"
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodGet, withQuery(path, query), nil, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) nicknameCommand(cfg Config, args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("usage: dnsid-board nickname set <room-id> --nickname <nickname>")
	}
	return a.nicknameSet(cfg, args[1:])
}

func (a app) nicknameSet(cfg Config, args []string) error {
	fs := flag.NewFlagSet("nickname set", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	nickname := fs.String("nickname", "", "")
	positionals, err := parseCommandFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: dnsid-board nickname set <room-id> --nickname <nickname>")
	}
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodPut, "/v1/rooms/"+url.PathEscape(positionals[0])+"/nickname", map[string]any{"nickname": *nickname}, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) allowlistCommand(cfg Config, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: dnsid-board allowlist <list|grant|revoke>")
	}
	switch args[0] {
	case "list":
		if len(args) != 2 {
			return errors.New("usage: dnsid-board allowlist list <room-id>")
		}
		return a.allowlistList(cfg, args[1])
	case "grant":
		return a.allowlistGrant(cfg, args[1:])
	case "revoke":
		return a.allowlistRevoke(cfg, args[1:])
	default:
		return fmt.Errorf("unknown allowlist command: %s", args[0])
	}
}

func (a app) allowlistList(cfg Config, roomID string) error {
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodGet, "/v1/rooms/"+url.PathEscape(roomID)+"/allowlist", nil, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) allowlistGrant(cfg Config, args []string) error {
	fs := flag.NewFlagSet("allowlist grant", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	agent := fs.String("agent", "", "")
	role := fs.String("role", "", "")
	positionals, err := parseCommandFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: dnsid-board allowlist grant <room-id> --agent <fqdn> --role <role>")
	}
	path := "/v1/rooms/" + url.PathEscape(positionals[0]) + "/allowlist/" + url.PathEscape(*agent)
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodPut, path, map[string]any{"role": *role}, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) allowlistRevoke(cfg Config, args []string) error {
	fs := flag.NewFlagSet("allowlist revoke", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	agent := fs.String("agent", "", "")
	positionals, err := parseCommandFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return errors.New("usage: dnsid-board allowlist revoke <room-id> --agent <fqdn>")
	}
	path := "/v1/rooms/" + url.PathEscape(positionals[0]) + "/allowlist/" + url.PathEscape(*agent)
	var response map[string]any
	if _, err := a.authRequest(context.Background(), cfg, http.MethodDelete, path, nil, nil, &response); err != nil {
		return err
	}
	return a.printGeneric(cfg, response)
}

func (a app) authRequest(ctx context.Context, cfg Config, method string, path string, body any, headers map[string]string, target any) (int64, error) {
	token, exp, err := a.token(ctx, cfg)
	if err != nil {
		return 0, err
	}
	if err := a.request(ctx, cfg, token, method, path, body, headers, target); err != nil {
		var apiErr apiError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			token, exp, err = a.token(ctx, cfg)
			if err != nil {
				return 0, err
			}
			return exp, a.request(ctx, cfg, token, method, path, body, headers, target)
		}
		return 0, err
	}
	return exp, nil
}

func (a app) token(ctx context.Context, cfg Config) (string, int64, error) {
	cmd := exec.CommandContext(ctx, cfg.DNSIDCLI, "--server", cfg.DNSIDServer, "token", "--domain", cfg.AgentDomain, "--audience", cfg.Audience)
	output, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", 0, errors.New("dnsid token failed")
		}
		return "", 0, err
	}
	token := strings.TrimSpace(string(output))
	exp, err := auth.UnsafeTokenExpiry(token)
	if err != nil {
		return "", 0, fmt.Errorf("dnsid token did not return a valid JWT: %w", err)
	}
	return token, exp, nil
}

func (a app) request(ctx context.Context, cfg Config, token string, method string, path string, body any, headers map[string]string, target any) error {
	endpoint := strings.TrimRight(cfg.APIEndpoint, "/") + path
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var problem struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &problem)
		if problem.Error.Message != "" {
			return apiError{Status: resp.StatusCode, Code: problem.Error.Code, Message: problem.Error.Message}
		}
		return apiError{Status: resp.StatusCode, Message: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	if target == nil {
		return nil
	}
	return json.Unmarshal(raw, target)
}

type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e apiError) Error() string {
	if e.Code != "" && e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Message
}

func (a app) printRoomCreate(cfg Config, response map[string]any) error {
	if cfg.OutputJSON {
		return printJSON(a.stdout, response)
	}
	room, _ := response["room"].(map[string]any)
	fmt.Fprintf(a.stdout, "room: %s\nname: %s\nowner: %s\n", room["room_id"], room["name"], room["owner"])
	return nil
}

func (a app) printGeneric(_ Config, response map[string]any) error {
	return printJSON(a.stdout, response)
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func withQuery(path string, query url.Values) string {
	if len(query) == 0 {
		return path
	}
	return path + "?" + query.Encode()
}

func parseCommandFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "--") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && flagTakesValue(fs, arg) {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positionals, nil
}

func flagTakesValue(fs *flag.FlagSet, arg string) bool {
	name := strings.TrimPrefix(arg, "--")
	if name == arg {
		return false
	}
	if idx := strings.Index(name, "="); idx >= 0 {
		name = name[:idx]
	}
	target := fs.Lookup(name)
	if target == nil {
		return false
	}
	if boolFlag, ok := target.Value.(interface{ IsBoolFlag() bool }); ok {
		return !boolFlag.IsBoolFlag()
	}
	return true
}

func randomID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}
