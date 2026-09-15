package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/auth"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/authorization"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/store"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/validation"
)

type Server struct {
	store      store.Store
	verifier   auth.Verifier
	authorizer authorization.Authorizer
}

func New(store store.Store, verifier auth.Verifier, authorizer authorization.Authorizer) *Server {
	return &Server{store: store, verifier: verifier, authorizer: authorizer}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/healthz" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	identity, err := s.authenticate(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		log.Printf("authentication failed: %v", err)
		writeError(w, http.StatusUnauthorized, "unauthorized", "Missing or invalid bearer token.")
		return
	}
	r = r.WithContext(auth.WithIdentity(r.Context(), identity))
	if err := s.route(w, r); err != nil {
		s.writeHandlerError(w, err)
	}
}

func (s *Server) route(w http.ResponseWriter, r *http.Request) error {
	segments, err := escapedSegments(r.URL.EscapedPath())
	if err != nil {
		return fmt.Errorf("%w: invalid path", board.ErrValidation)
	}
	if len(segments) == 2 && segments[0] == "v1" && segments[1] == "whoami" && r.Method == http.MethodGet {
		return s.whoami(w, r)
	}
	if len(segments) == 2 && segments[0] == "v1" && segments[1] == "rooms" {
		switch r.Method {
		case http.MethodPost:
			return s.createRoom(w, r)
		case http.MethodGet:
			return s.listRooms(w, r)
		}
	}
	if len(segments) >= 3 && segments[0] == "v1" && segments[1] == "rooms" {
		roomID := segments[2]
		if len(segments) == 3 && r.Method == http.MethodGet {
			return s.getRoom(w, r, roomID)
		}
		if len(segments) == 4 && segments[3] == "messages" {
			switch r.Method {
			case http.MethodGet:
				return s.readMessages(w, r, roomID)
			case http.MethodPost:
				return s.postMessage(w, r, roomID)
			}
		}
		if len(segments) == 4 && segments[3] == "nickname" && r.Method == http.MethodPut {
			return s.setNickname(w, r, roomID)
		}
		if len(segments) == 4 && segments[3] == "allowlist" && r.Method == http.MethodGet {
			return s.listAllowlist(w, r, roomID)
		}
		if len(segments) == 5 && segments[3] == "allowlist" {
			switch r.Method {
			case http.MethodPut:
				return s.grantAllowlist(w, r, roomID, segments[4])
			case http.MethodDelete:
				return s.revokeAllowlist(w, r, roomID, segments[4])
			}
		}
	}
	writeError(w, http.StatusNotFound, "not_found", "Endpoint not found.")
	return nil
}

func (s *Server) authenticate(ctx context.Context, header string) (board.Identity, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return board.Identity{}, auth.ErrUnauthorized
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if token == "" {
		return board.Identity{}, auth.ErrUnauthorized
	}
	return s.verifier.VerifyBearer(ctx, token)
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) error {
	identity, err := auth.RequireIdentity(r.Context())
	if err != nil {
		return err
	}
	audience := ""
	if len(identity.Audience) > 0 {
		audience = identity.Audience[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"agent":             identity.Agent,
		"issuer":            identity.Issuer,
		"audience":          audience,
		"environment":       identity.Environment,
		"token_jti_present": identity.TokenJTIHash != "",
	})
	return nil
}

func (s *Server) createRoom(w http.ResponseWriter, r *http.Request) error {
	identity, _ := auth.RequireIdentity(r.Context())
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionCreateRoom, board.AuthSnapshot{}, board.AuthContext{}); err != nil {
		return err
	}
	var input struct {
		RoomID      string `json:"room_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	room, err := s.store.CreateRoom(r.Context(), identity, store.CreateRoomInput{
		RoomID:       input.RoomID,
		Name:         input.Name,
		Description:  input.Description,
		TokenJTIHash: identity.TokenJTIHash,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true,
		"room": map[string]any{
			"room_id":    room.RoomID,
			"name":       room.Name,
			"owner":      room.Owner,
			"created_at": room.CreatedAt,
		},
	})
	return nil
}

func (s *Server) listRooms(w http.ResponseWriter, r *http.Request) error {
	identity, _ := auth.RequireIdentity(r.Context())
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionListOwnRooms, board.AuthSnapshot{}, board.AuthContext{}); err != nil {
		return err
	}
	limit, err := queryLimit(r, board.DefaultListLimit)
	if err != nil {
		return err
	}
	page, err := s.store.ListRooms(r.Context(), identity.Agent, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rooms": page.Items, "next_cursor": nullable(page.NextCursor)})
	return nil
}

func (s *Server) getRoom(w http.ResponseWriter, r *http.Request, roomID string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionConnectRoom, snapshot, board.AuthContext{}); err != nil {
		return err
	}
	role, capabilities := ownRole(snapshot)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"room": map[string]any{
			"room_id":      snapshot.Room.RoomID,
			"name":         snapshot.Room.Name,
			"description":  snapshot.Room.Description,
			"owner":        snapshot.Room.Owner,
			"archived":     snapshot.Room.Archived,
			"role":         role,
			"nickname":     ownNickname(snapshot),
			"capabilities": capabilities,
			"created_at":   snapshot.Room.CreatedAt,
			"updated_at":   snapshot.Room.UpdatedAt,
		},
	})
	return nil
}

func (s *Server) readMessages(w http.ResponseWriter, r *http.Request, roomID string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	limit, err := queryLimit(r, board.DefaultMessagesLimit)
	if err != nil {
		return err
	}
	waitSeconds, err := queryWait(r)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for {
		snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
		if err != nil {
			return err
		}
		if err := s.authorizer.Authorize(r.Context(), identity, board.ActionReadMessages, snapshot, board.AuthContext{}); err != nil {
			return err
		}
		page, err := s.store.ReadMessages(r.Context(), roomID, limit, r.URL.Query().Get("cursor"), r.URL.Query().Get("after"))
		if err != nil {
			return err
		}
		if len(page.Items) > 0 || waitSeconds == 0 || time.Now().After(deadline) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "messages": page.Items, "next_cursor": nullable(page.NextCursor)})
			return nil
		}
		select {
		case <-r.Context().Done():
			return r.Context().Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *Server) postMessage(w http.ResponseWriter, r *http.Request, roomID string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotencyKey == "" {
		return fmt.Errorf("%w: Idempotency-Key is required", board.ErrValidation)
	}
	var raw map[string]json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return err
	}
	if containsIdentityField(raw) {
		return fmt.Errorf("%w: identity fields are not accepted in message bodies", board.ErrValidation)
	}
	var body string
	if err := json.Unmarshal(raw["body"], &body); err != nil {
		return fmt.Errorf("%w: body is required", board.ErrValidation)
	}
	body, err := validation.MessageBody(body)
	if err != nil {
		return fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionPostMessage, snapshot, board.AuthContext{}); err != nil {
		return err
	}
	requestHash := requestHash(body)
	actorVersion := int64(0)
	authorNickname := ""
	if snapshot.Membership != nil {
		actorVersion = snapshot.Membership.Version
		authorNickname = snapshot.Membership.Nickname
	}
	result, err := s.store.PostMessage(r.Context(), identity, store.PostInput{
		RoomID:             roomID,
		Body:               body,
		AuthorNickname:     authorNickname,
		IdempotencyKey:     idempotencyKey,
		RequestHash:        requestHash,
		ActorMemberVersion: actorVersion,
	})
	if err != nil {
		return err
	}
	status := http.StatusCreated
	if result.IdempotentReplay {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"ok": true, "message": result.Message, "idempotent_replay": result.IdempotentReplay})
	return nil
}

func (s *Server) setNickname(w http.ResponseWriter, r *http.Request, roomID string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	var input struct {
		Nickname string `json:"nickname"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionUpdateNickname, snapshot, board.AuthContext{}); err != nil {
		return err
	}
	actorVersion := int64(0)
	if snapshot.Membership != nil {
		actorVersion = snapshot.Membership.Version
	}
	member, err := s.store.SetNickname(r.Context(), identity, store.SetNicknameInput{
		RoomID:             roomID,
		Nickname:           input.Nickname,
		ActorMemberVersion: actorVersion,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"profile": map[string]any{
			"room_id":    member.RoomID,
			"agent":      member.Agent,
			"nickname":   member.Nickname,
			"updated_at": member.UpdatedAt,
		},
	})
	return nil
}

func (s *Server) listAllowlist(w http.ResponseWriter, r *http.Request, roomID string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
	if err != nil {
		return err
	}
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionViewAllowList, snapshot, board.AuthContext{}); err != nil {
		return err
	}
	limit, err := queryLimit(r, board.DefaultListLimit)
	if err != nil {
		return err
	}
	page, err := s.store.ListAllowlist(r.Context(), roomID, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entries": page.Items, "next_cursor": nullable(page.NextCursor)})
	return nil
}

func (s *Server) grantAllowlist(w http.ResponseWriter, r *http.Request, roomID string, agent string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	target, err := validation.CanonicalDNSName(agent)
	if err != nil {
		return fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	var input struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	role, ok := board.MutableRole(input.Role)
	if !ok {
		return fmt.Errorf("%w: role must be admin, poster, reader, or connector", board.ErrValidation)
	}
	snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
	if err != nil {
		return err
	}
	authContext := board.AuthContext{Operation: "grant", TargetAgent: target, NewRole: role}
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionUpdateAllowList, snapshot, authContext); err != nil {
		return err
	}
	actorVersion := int64(0)
	if snapshot.Membership != nil {
		actorVersion = snapshot.Membership.Version
	}
	entry, created, err := s.store.GrantAllowlist(r.Context(), identity, store.GrantInput{
		RoomID:              roomID,
		TargetAgent:         target,
		Role:                role,
		TokenJTIHash:        identity.TokenJTIHash,
		ActorMemberVersion:  actorVersion,
		ExpectedRoomVersion: snapshot.Room.Version,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "entry": entry, "created": created})
	return nil
}

func (s *Server) revokeAllowlist(w http.ResponseWriter, r *http.Request, roomID string, agent string) error {
	identity, _ := auth.RequireIdentity(r.Context())
	target, err := validation.CanonicalDNSName(agent)
	if err != nil {
		return fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	snapshot, err := s.store.GetRoomForAgent(r.Context(), roomID, identity.Agent)
	if err != nil {
		return err
	}
	authContext := board.AuthContext{Operation: "remove", TargetAgent: target}
	if err := s.authorizer.Authorize(r.Context(), identity, board.ActionUpdateAllowList, snapshot, authContext); err != nil {
		return err
	}
	actorVersion := int64(0)
	if snapshot.Membership != nil {
		actorVersion = snapshot.Membership.Version
	}
	removed, err := s.store.RevokeAllowlist(r.Context(), identity, store.RevokeInput{
		RoomID:              roomID,
		TargetAgent:         target,
		TokenJTIHash:        identity.TokenJTIHash,
		ActorMemberVersion:  actorVersion,
		ExpectedRoomVersion: snapshot.Room.Version,
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
	return nil
}

func (s *Server) writeHandlerError(w http.ResponseWriter, err error) {
	log.Printf("request failed: %v", err)
	switch {
	case errors.Is(err, board.ErrValidation):
		writeError(w, http.StatusBadRequest, "validation_error", err.Error())
	case errors.Is(err, board.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, board.ErrDenied), errors.Is(err, board.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Room not found.")
	case errors.Is(err, board.ErrDependency):
		writeError(w, http.StatusServiceUnavailable, "dependency_unavailable", "A required dependency is unavailable.")
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "Internal server error.")
	}
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return fmt.Errorf("%w: request body is required", board.ErrValidation)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: invalid JSON body", board.ErrValidation)
	}
	return nil
}

func queryLimit(r *http.Request, defaultLimit int) (int, error) {
	value := r.URL.Query().Get("limit")
	if value == "" {
		return defaultLimit, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%w: limit must be positive", board.ErrValidation)
	}
	return board.BoundLimit(parsed, defaultLimit), nil
}

func queryWait(r *http.Request) (int, error) {
	value := r.URL.Query().Get("wait")
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("%w: wait must be non-negative", board.ErrValidation)
	}
	if parsed > board.MaxWatchSeconds {
		return board.MaxWatchSeconds, nil
	}
	return parsed, nil
}

func escapedSegments(escapedPath string) ([]string, error) {
	trimmed := strings.Trim(escapedPath, "/")
	if trimmed == "" {
		return nil, nil
	}
	raw := strings.Split(trimmed, "/")
	segments := make([]string, 0, len(raw))
	for _, segment := range raw {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return nil, err
		}
		segments = append(segments, decoded)
	}
	return segments, nil
}

func containsIdentityField(raw map[string]json.RawMessage) bool {
	for key := range raw {
		switch strings.ToLower(key) {
		case "agent", "sub", "dnsid", "x-dnsid-sub", "accountable_entity", "nickname", "author_nickname", "display_name":
			return true
		}
	}
	return false
}

func ownRole(snapshot board.AuthSnapshot) (board.Role, []board.Capability) {
	if snapshot.Membership == nil {
		return "", nil
	}
	return snapshot.Membership.Role, snapshot.Membership.Capabilities
}

func ownNickname(snapshot board.AuthSnapshot) string {
	if snapshot.Membership == nil {
		return ""
	}
	return snapshot.Membership.Nickname
}

func requestHash(body string) string {
	hash := sha256.Sum256([]byte(body))
	return "sha256:" + base64.RawURLEncoding.EncodeToString(hash[:])
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"ok": false,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
