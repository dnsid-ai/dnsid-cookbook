package board

import (
	"errors"
	"time"
)

const (
	DefaultListLimit     = 25
	DefaultMessagesLimit = 50
	MaxLimit             = 100
	MaxWatchSeconds      = 25
	MaxMessageBytes      = 8 * 1024
	MaxNicknameLength    = 32
	SchemaVersion        = 1
)

type Role string

const (
	RoleOwner     Role = "owner"
	RoleAdmin     Role = "admin"
	RolePoster    Role = "poster"
	RoleReader    Role = "reader"
	RoleConnector Role = "connector"
)

type Capability string

const (
	CapabilityOwner   Capability = "owner"
	CapabilityManage  Capability = "manage"
	CapabilityPost    Capability = "post"
	CapabilityRead    Capability = "read"
	CapabilityConnect Capability = "connect"
)

type Action string

const (
	ActionCreateRoom      Action = "CreateRoom"
	ActionListOwnRooms    Action = "ListOwnRooms"
	ActionConnectRoom     Action = "ConnectRoom"
	ActionReadMessages    Action = "ReadMessages"
	ActionPostMessage     Action = "PostMessage"
	ActionUpdateNickname  Action = "UpdateNickname"
	ActionViewAllowList   Action = "ViewAllowList"
	ActionUpdateAllowList Action = "UpdateAllowList"
)

var (
	ErrNotFound          = errors.New("not found")
	ErrConflict          = errors.New("conflict")
	ErrDenied            = errors.New("denied")
	ErrValidation        = errors.New("validation error")
	ErrDependency        = errors.New("dependency error")
	ErrIdempotencyReplay = errors.New("idempotent replay")
)

type Identity struct {
	Agent        string   `json:"agent"`
	Issuer       string   `json:"issuer"`
	Audience     []string `json:"audience"`
	Environment  string   `json:"environment"`
	TokenJTIHash string   `json:"token_jti_hash,omitempty"`
	ExpiresAt    int64    `json:"expires_at,omitempty"`
}

type Room struct {
	RoomID      string    `json:"room_id"`
	RoomKey     string    `json:"room_key,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Owner       string    `json:"owner"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Version     int64     `json:"version,omitempty"`
	Archived    bool      `json:"archived"`
	MemberCount int64     `json:"member_count,omitempty"`
}

type Membership struct {
	RoomID       string       `json:"room_id,omitempty"`
	RoomKey      string       `json:"room_key,omitempty"`
	Agent        string       `json:"agent"`
	Nickname     string       `json:"nickname,omitempty"`
	NicknameKey  string       `json:"-"`
	Role         Role         `json:"role"`
	Capabilities []Capability `json:"capabilities"`
	CreatedBy    string       `json:"created_by,omitempty"`
	UpdatedBy    string       `json:"updated_by,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	Version      int64        `json:"version,omitempty"`
}

type RoomSummary struct {
	RoomID       string       `json:"room_id"`
	Name         string       `json:"name"`
	Description  string       `json:"description,omitempty"`
	Owner        string       `json:"owner"`
	Role         Role         `json:"role"`
	Capabilities []Capability `json:"capabilities"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type Message struct {
	RoomID         string     `json:"room_id,omitempty"`
	RoomKey        string     `json:"room_key,omitempty"`
	MessageID      string     `json:"message_id"`
	Author         string     `json:"author"`
	AuthorNickname string     `json:"author_nickname,omitempty"`
	Body           string     `json:"body"`
	CreatedAt      time.Time  `json:"created_at"`
	IdempotencyKey string     `json:"-"`
	RequestHash    string     `json:"-"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

type AuthSnapshot struct {
	Room       Room
	Membership *Membership
}

type AuthContext struct {
	Operation   string
	TargetAgent string
	NewRole     Role
}

type Page[T any] struct {
	Items      []T
	NextCursor string
}

type PostResult struct {
	Message             Message
	IdempotentReplay    bool
	IdempotencyConflict bool
}

func CapabilitiesForRole(role Role) ([]Capability, bool) {
	switch role {
	case RoleOwner:
		return []Capability{CapabilityOwner, CapabilityManage, CapabilityPost, CapabilityRead, CapabilityConnect}, true
	case RoleAdmin:
		return []Capability{CapabilityManage, CapabilityPost, CapabilityRead, CapabilityConnect}, true
	case RolePoster:
		return []Capability{CapabilityPost, CapabilityRead, CapabilityConnect}, true
	case RoleReader:
		return []Capability{CapabilityRead, CapabilityConnect}, true
	case RoleConnector:
		return []Capability{CapabilityConnect}, true
	default:
		return nil, false
	}
}

func ParseRole(value string) (Role, bool) {
	role := Role(value)
	_, ok := CapabilitiesForRole(role)
	return role, ok
}

func MutableRole(value string) (Role, bool) {
	role, ok := ParseRole(value)
	if !ok || role == RoleOwner {
		return "", false
	}
	return role, true
}

func RoleCan(role Role, action Action) bool {
	switch action {
	case ActionCreateRoom, ActionListOwnRooms:
		return true
	case ActionConnectRoom:
		return role == RoleOwner || role == RoleAdmin || role == RolePoster || role == RoleReader || role == RoleConnector
	case ActionReadMessages:
		return role == RoleOwner || role == RoleAdmin || role == RolePoster || role == RoleReader
	case ActionPostMessage:
		return role == RoleOwner || role == RoleAdmin || role == RolePoster
	case ActionUpdateNickname:
		return role == RoleOwner || role == RoleAdmin || role == RolePoster || role == RoleReader || role == RoleConnector
	case ActionViewAllowList, ActionUpdateAllowList:
		return role == RoleOwner || role == RoleAdmin
	default:
		return false
	}
}

func BoundLimit(limit int, defaultLimit int) int {
	if defaultLimit <= 0 {
		defaultLimit = DefaultListLimit
	}
	if limit <= 0 {
		return defaultLimit
	}
	if limit > MaxLimit {
		return MaxLimit
	}
	return limit
}
