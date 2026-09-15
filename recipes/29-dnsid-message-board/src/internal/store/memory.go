package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/validation"
)

type MemoryStore struct {
	mu       sync.Mutex
	rooms    map[string]*roomRecord
	roomKeys map[string]string
	quotas   map[string]int64
	now      func() time.Time

	MaxRoomsPerAgent  int64
	MaxMembersPerRoom int64
}

type roomRecord struct {
	room        board.Room
	members     map[string]board.Membership
	nicknames   map[string]string
	messages    []board.Message
	idempotency map[string]idempotencyRecord
	audits      []auditRecord
}

type idempotencyRecord struct {
	RequestHash string
	MessageID   string
}

type auditRecord struct {
	EventType    string
	Actor        string
	TargetAgent  string
	Role         board.Role
	TokenJTIHash string
	CreatedAt    time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		rooms:             map[string]*roomRecord{},
		roomKeys:          map[string]string{},
		quotas:            map[string]int64{},
		now:               time.Now,
		MaxRoomsPerAgent:  50,
		MaxMembersPerRoom: 100,
	}
}

func (s *MemoryStore) CreateRoom(_ context.Context, actor board.Identity, input CreateRoomInput) (board.Room, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.Room{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, err := validation.RoomKey(roomID)
	if err != nil {
		return board.Room{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	now := s.now().UTC()
	name := input.Name
	if name == "" {
		name = roomID
	}
	capabilities, _ := board.CapabilitiesForRole(board.RoleOwner)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roomKeys[roomID]; exists {
		return board.Room{}, board.ErrConflict
	}
	if s.quotas[actor.Agent] >= s.MaxRoomsPerAgent {
		return board.Room{}, fmt.Errorf("%w: room quota exceeded", board.ErrValidation)
	}
	room := board.Room{
		RoomID:      roomID,
		RoomKey:     roomKey,
		Name:        name,
		Description: input.Description,
		Owner:       actor.Agent,
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
		Archived:    false,
		MemberCount: 1,
	}
	owner := board.Membership{
		RoomID:       roomID,
		RoomKey:      roomKey,
		Agent:        actor.Agent,
		Role:         board.RoleOwner,
		Capabilities: capabilities,
		CreatedBy:    actor.Agent,
		UpdatedBy:    actor.Agent,
		CreatedAt:    now,
		UpdatedAt:    now,
		Version:      1,
	}
	s.roomKeys[roomID] = roomKey
	s.rooms[roomKey] = &roomRecord{
		room:        room,
		members:     map[string]board.Membership{actor.Agent: owner},
		nicknames:   map[string]string{},
		idempotency: map[string]idempotencyRecord{},
		audits: []auditRecord{{
			EventType:    "room_created",
			Actor:        actor.Agent,
			TargetAgent:  actor.Agent,
			Role:         board.RoleOwner,
			TokenJTIHash: input.TokenJTIHash,
			CreatedAt:    now,
		}},
	}
	s.quotas[actor.Agent]++
	return room, nil
}

func (s *MemoryStore) ListRooms(_ context.Context, agent string, limit int, cursor string) (board.Page[board.RoomSummary], error) {
	limit = board.BoundLimit(limit, board.DefaultListLimit)
	offset, err := decodeOffset(cursor)
	if err != nil {
		return board.Page[board.RoomSummary]{}, fmt.Errorf("%w: invalid cursor", board.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var summaries []board.RoomSummary
	for _, rec := range s.rooms {
		member, ok := rec.members[agent]
		if !ok {
			continue
		}
		summaries = append(summaries, board.RoomSummary{
			RoomID:       rec.room.RoomID,
			Name:         rec.room.Name,
			Description:  rec.room.Description,
			Owner:        rec.room.Owner,
			Role:         member.Role,
			Capabilities: append([]board.Capability(nil), member.Capabilities...),
			UpdatedAt:    rec.room.UpdatedAt,
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].UpdatedAt.Equal(summaries[j].UpdatedAt) {
			return summaries[i].RoomID < summaries[j].RoomID
		}
		return summaries[i].UpdatedAt.After(summaries[j].UpdatedAt)
	})
	return pageSlice(summaries, offset, limit)
}

func (s *MemoryStore) GetRoomForAgent(_ context.Context, roomID string, agent string) (board.AuthSnapshot, error) {
	roomID, err := validation.NormalizeRoomID(roomID)
	if err != nil {
		return board.AuthSnapshot{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return board.AuthSnapshot{}, err
	}
	snapshot := board.AuthSnapshot{Room: rec.room}
	if member, ok := rec.members[agent]; ok {
		copyMember := member
		copyMember.Capabilities = append([]board.Capability(nil), member.Capabilities...)
		snapshot.Membership = &copyMember
	}
	return snapshot, nil
}

func (s *MemoryStore) ListAllowlist(_ context.Context, roomID string, limit int, cursor string) (board.Page[board.Membership], error) {
	limit = board.BoundLimit(limit, board.DefaultListLimit)
	offset, err := decodeOffset(cursor)
	if err != nil {
		return board.Page[board.Membership]{}, fmt.Errorf("%w: invalid cursor", board.ErrValidation)
	}
	roomID, err = validation.NormalizeRoomID(roomID)
	if err != nil {
		return board.Page[board.Membership]{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return board.Page[board.Membership]{}, err
	}
	entries := make([]board.Membership, 0, len(rec.members))
	for _, member := range rec.members {
		member.Capabilities = append([]board.Capability(nil), member.Capabilities...)
		entries = append(entries, member)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Role == board.RoleOwner {
			return true
		}
		if entries[j].Role == board.RoleOwner {
			return false
		}
		return entries[i].Agent < entries[j].Agent
	})
	return pageSlice(entries, offset, limit)
}

func (s *MemoryStore) GrantAllowlist(_ context.Context, actor board.Identity, input GrantInput) (board.Membership, bool, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.Membership{}, false, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	target, err := validation.CanonicalDNSName(input.TargetAgent)
	if err != nil {
		return board.Membership{}, false, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	capabilities, ok := board.CapabilitiesForRole(input.Role)
	if !ok || input.Role == board.RoleOwner {
		return board.Membership{}, false, fmt.Errorf("%w: invalid role", board.ErrValidation)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return board.Membership{}, false, err
	}
	if rec.room.Archived || rec.room.Version != input.ExpectedRoomVersion {
		return board.Membership{}, false, board.ErrConflict
	}
	if target == actor.Agent {
		return board.Membership{}, false, board.ErrDenied
	}
	if target == rec.room.Owner {
		return board.Membership{}, false, board.ErrDenied
	}
	if err := checkActorLocked(rec, actor.Agent, input.ActorMemberVersion, board.ActionUpdateAllowList); err != nil {
		return board.Membership{}, false, err
	}
	existing, exists := rec.members[target]
	if !exists && rec.room.MemberCount >= s.MaxMembersPerRoom {
		return board.Membership{}, false, fmt.Errorf("%w: member quota exceeded", board.ErrValidation)
	}
	if exists && existing.Role == input.Role {
		existing.Capabilities = append([]board.Capability(nil), existing.Capabilities...)
		return existing, false, nil
	}
	member := board.Membership{
		RoomID:       rec.room.RoomID,
		RoomKey:      rec.room.RoomKey,
		Agent:        target,
		Role:         input.Role,
		Capabilities: capabilities,
		UpdatedBy:    actor.Agent,
		UpdatedAt:    now,
	}
	if exists {
		if existing.Role == board.RoleOwner {
			return board.Membership{}, false, board.ErrDenied
		}
		member.Nickname = existing.Nickname
		member.NicknameKey = existing.NicknameKey
		member.CreatedBy = existing.CreatedBy
		member.CreatedAt = existing.CreatedAt
		member.Version = existing.Version + 1
	} else {
		member.CreatedBy = actor.Agent
		member.CreatedAt = now
		member.Version = 1
		rec.room.MemberCount++
	}
	rec.members[target] = member
	rec.room.Version++
	rec.room.UpdatedAt = now
	rec.audits = append(rec.audits, auditRecord{
		EventType:    "allowlist_granted",
		Actor:        actor.Agent,
		TargetAgent:  target,
		Role:         input.Role,
		TokenJTIHash: input.TokenJTIHash,
		CreatedAt:    now,
	})
	return member, !exists, nil
}

func (s *MemoryStore) RevokeAllowlist(_ context.Context, actor board.Identity, input RevokeInput) (bool, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	target, err := validation.CanonicalDNSName(input.TargetAgent)
	if err != nil {
		return false, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return false, err
	}
	if rec.room.Archived || rec.room.Version != input.ExpectedRoomVersion {
		return false, board.ErrConflict
	}
	if target == actor.Agent {
		return false, board.ErrDenied
	}
	if target == rec.room.Owner {
		return false, board.ErrDenied
	}
	if err := checkActorLocked(rec, actor.Agent, input.ActorMemberVersion, board.ActionUpdateAllowList); err != nil {
		return false, err
	}
	member, exists := rec.members[target]
	if !exists {
		return false, board.ErrNotFound
	}
	if member.Role == board.RoleOwner {
		return false, board.ErrDenied
	}
	if member.NicknameKey != "" {
		delete(rec.nicknames, member.NicknameKey)
	}
	delete(rec.members, target)
	rec.room.MemberCount--
	rec.room.Version++
	rec.room.UpdatedAt = now
	rec.audits = append(rec.audits, auditRecord{
		EventType:    "allowlist_revoked",
		Actor:        actor.Agent,
		TargetAgent:  target,
		TokenJTIHash: input.TokenJTIHash,
		CreatedAt:    now,
	})
	return true, nil
}

func (s *MemoryStore) SetNickname(_ context.Context, actor board.Identity, input SetNicknameInput) (board.Membership, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.Membership{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	nickname, nicknameKey, err := validation.Nickname(input.Nickname)
	if err != nil {
		return board.Membership{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return board.Membership{}, err
	}
	if rec.room.Archived {
		return board.Membership{}, board.ErrDenied
	}
	member, ok := rec.members[actor.Agent]
	if !ok {
		return board.Membership{}, board.ErrDenied
	}
	if input.ActorMemberVersion != 0 && member.Version != input.ActorMemberVersion {
		return board.Membership{}, board.ErrConflict
	}
	if !board.RoleCan(member.Role, board.ActionUpdateNickname) {
		return board.Membership{}, board.ErrDenied
	}
	if owner, exists := rec.nicknames[nicknameKey]; exists && owner != actor.Agent {
		return board.Membership{}, board.ErrConflict
	}
	if member.Nickname == nickname && member.NicknameKey == nicknameKey {
		member.Capabilities = append([]board.Capability(nil), member.Capabilities...)
		return member, nil
	}
	if member.NicknameKey != "" && member.NicknameKey != nicknameKey {
		delete(rec.nicknames, member.NicknameKey)
	}
	rec.nicknames[nicknameKey] = actor.Agent
	member.Nickname = nickname
	member.NicknameKey = nicknameKey
	member.UpdatedBy = actor.Agent
	member.UpdatedAt = now
	member.Version++
	rec.members[actor.Agent] = member
	member.Capabilities = append([]board.Capability(nil), member.Capabilities...)
	return member, nil
}

func (s *MemoryStore) PostMessage(_ context.Context, actor board.Identity, input PostInput) (board.PostResult, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.PostResult{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	if input.IdempotencyKey == "" {
		return board.PostResult{}, fmt.Errorf("%w: idempotency key is required", board.ErrValidation)
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return board.PostResult{}, err
	}
	if rec.room.Archived {
		return board.PostResult{}, board.ErrDenied
	}
	if err := checkActorLocked(rec, actor.Agent, input.ActorMemberVersion, board.ActionPostMessage); err != nil {
		return board.PostResult{}, err
	}
	idempotencyKey := actor.Agent + "#" + input.IdempotencyKey
	if idem, ok := rec.idempotency[idempotencyKey]; ok {
		if idem.RequestHash != input.RequestHash {
			return board.PostResult{IdempotencyConflict: true}, board.ErrConflict
		}
		for _, msg := range rec.messages {
			if msg.MessageID == idem.MessageID {
				return board.PostResult{Message: msg, IdempotentReplay: true}, nil
			}
		}
		return board.PostResult{}, board.ErrConflict
	}
	message := board.Message{
		RoomID:         rec.room.RoomID,
		RoomKey:        rec.room.RoomKey,
		MessageID:      "msg_" + ulid.Make().String(),
		Author:         actor.Agent,
		AuthorNickname: input.AuthorNickname,
		Body:           input.Body,
		CreatedAt:      now,
		IdempotencyKey: input.IdempotencyKey,
		RequestHash:    input.RequestHash,
	}
	rec.messages = append(rec.messages, message)
	sort.Slice(rec.messages, func(i, j int) bool {
		return rec.messages[i].MessageID < rec.messages[j].MessageID
	})
	rec.idempotency[idempotencyKey] = idempotencyRecord{RequestHash: input.RequestHash, MessageID: message.MessageID}
	return board.PostResult{Message: message}, nil
}

func (s *MemoryStore) ReadMessages(_ context.Context, roomID string, limit int, cursor string, after string) (board.Page[board.Message], error) {
	limit = board.BoundLimit(limit, board.DefaultMessagesLimit)
	offset, err := decodeOffset(cursor)
	if err != nil {
		return board.Page[board.Message]{}, fmt.Errorf("%w: invalid cursor", board.ErrValidation)
	}
	roomID, err = validation.NormalizeRoomID(roomID)
	if err != nil {
		return board.Page[board.Message]{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.recordByRoomIDLocked(roomID)
	if err != nil {
		return board.Page[board.Message]{}, err
	}
	if after != "" {
		start := offset
		if cursor == "" {
			start = sort.Search(len(rec.messages), func(i int) bool {
				return rec.messages[i].MessageID > after
			})
		}
		return pageSlice(rec.messages, start, limit)
	}
	end := offset
	if cursor == "" || end > len(rec.messages) {
		end = len(rec.messages)
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	page := board.Page[board.Message]{Items: append([]board.Message(nil), rec.messages[start:end]...)}
	if start > 0 {
		page.NextCursor = encodeOffset(start)
	}
	return page, nil
}

func (s *MemoryStore) recordByRoomIDLocked(roomID string) (*roomRecord, error) {
	roomKey, ok := s.roomKeys[roomID]
	if !ok {
		return nil, board.ErrNotFound
	}
	rec, ok := s.rooms[roomKey]
	if !ok {
		return nil, board.ErrNotFound
	}
	return rec, nil
}

func checkActorLocked(rec *roomRecord, agent string, expectedVersion int64, action board.Action) error {
	member, ok := rec.members[agent]
	if !ok {
		return board.ErrDenied
	}
	if expectedVersion != 0 && member.Version != expectedVersion {
		return board.ErrConflict
	}
	if !board.RoleCan(member.Role, action) {
		return board.ErrDenied
	}
	return nil
}

type offsetCursor struct {
	Offset int `json:"offset"`
}

func decodeOffset(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, err
	}
	var decoded offsetCursor
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return 0, err
	}
	if decoded.Offset < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	return decoded.Offset, nil
}

func encodeOffset(offset int) string {
	raw, _ := json.Marshal(offsetCursor{Offset: offset})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func pageSlice[T any](items []T, offset int, limit int) (board.Page[T], error) {
	if offset > len(items) {
		return board.Page[T]{Items: []T{}}, nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	page := board.Page[T]{Items: append([]T(nil), items[offset:end]...)}
	if end < len(items) {
		page.NextCursor = encodeOffset(end)
	}
	return page, nil
}
