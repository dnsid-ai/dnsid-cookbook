package store

import (
	"context"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

type CreateRoomInput struct {
	RoomID       string
	Name         string
	Description  string
	TokenJTIHash string
}

type GrantInput struct {
	RoomID              string
	TargetAgent         string
	Role                board.Role
	TokenJTIHash        string
	ActorMemberVersion  int64
	ExpectedRoomVersion int64
}

type RevokeInput struct {
	RoomID              string
	TargetAgent         string
	TokenJTIHash        string
	ActorMemberVersion  int64
	ExpectedRoomVersion int64
}

type PostInput struct {
	RoomID             string
	Body               string
	AuthorNickname     string
	IdempotencyKey     string
	RequestHash        string
	ActorMemberVersion int64
}

type SetNicknameInput struct {
	RoomID             string
	Nickname           string
	ActorMemberVersion int64
}

type Store interface {
	CreateRoom(ctx context.Context, actor board.Identity, input CreateRoomInput) (board.Room, error)
	ListRooms(ctx context.Context, agent string, limit int, cursor string) (board.Page[board.RoomSummary], error)
	GetRoomForAgent(ctx context.Context, roomID string, agent string) (board.AuthSnapshot, error)
	ListAllowlist(ctx context.Context, roomID string, limit int, cursor string) (board.Page[board.Membership], error)
	GrantAllowlist(ctx context.Context, actor board.Identity, input GrantInput) (board.Membership, bool, error)
	RevokeAllowlist(ctx context.Context, actor board.Identity, input RevokeInput) (bool, error)
	SetNickname(ctx context.Context, actor board.Identity, input SetNicknameInput) (board.Membership, error)
	PostMessage(ctx context.Context, actor board.Identity, input PostInput) (board.PostResult, error)
	ReadMessages(ctx context.Context, roomID string, limit int, cursor string, after string) (board.Page[board.Message], error)
}
