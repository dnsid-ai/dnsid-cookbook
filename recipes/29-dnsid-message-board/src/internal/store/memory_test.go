package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

func TestMemoryStoreRoomMembershipIdempotencyAndRevocation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	owner := board.Identity{Agent: "owner.example.com"}
	poster := board.Identity{Agent: "poster.example.com"}

	room, err := s.CreateRoom(ctx, owner, CreateRoomInput{RoomID: "security/risk brainstorm", Name: "Security"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRoom(ctx, owner, CreateRoomInput{RoomID: "security/risk brainstorm"}); !errors.Is(err, board.ErrConflict) {
		t.Fatalf("duplicate room error = %v", err)
	}
	snapshot, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	entry, created, err := s.GrantAllowlist(ctx, owner, GrantInput{
		RoomID:              room.RoomID,
		TargetAgent:         poster.Agent,
		Role:                board.RolePoster,
		ActorMemberVersion:  snapshot.Membership.Version,
		ExpectedRoomVersion: snapshot.Room.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || entry.Agent != poster.Agent {
		t.Fatalf("unexpected grant: created=%v entry=%+v", created, entry)
	}
	ownerSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	repeated, created, err := s.GrantAllowlist(ctx, owner, GrantInput{
		RoomID:              room.RoomID,
		TargetAgent:         poster.Agent,
		Role:                board.RolePoster,
		ActorMemberVersion:  ownerSnapshot.Membership.Version,
		ExpectedRoomVersion: ownerSnapshot.Room.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created || repeated.Version != entry.Version {
		t.Fatalf("same-role grant should be a no-op after auth, created=%v entry=%+v", created, repeated)
	}
	afterRepeated, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if afterRepeated.Room.Version != ownerSnapshot.Room.Version {
		t.Fatalf("same-role grant changed room version: got %d want %d", afterRepeated.Room.Version, ownerSnapshot.Room.Version)
	}
	admin := board.Identity{Agent: "admin.example.com"}
	adminEntry, created, err := s.GrantAllowlist(ctx, owner, GrantInput{
		RoomID:              room.RoomID,
		TargetAgent:         admin.Agent,
		Role:                board.RoleAdmin,
		ActorMemberVersion:  afterRepeated.Membership.Version,
		ExpectedRoomVersion: afterRepeated.Room.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || adminEntry.Role != board.RoleAdmin {
		t.Fatalf("unexpected admin grant: created=%v entry=%+v", created, adminEntry)
	}
	adminSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, admin.Agent)
	if err != nil {
		t.Fatal(err)
	}
	latestOwnerSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GrantAllowlist(ctx, admin, GrantInput{
		RoomID:              room.RoomID,
		TargetAgent:         admin.Agent,
		Role:                board.RoleReader,
		ActorMemberVersion:  adminSnapshot.Membership.Version,
		ExpectedRoomVersion: latestOwnerSnapshot.Room.Version,
	}); !errors.Is(err, board.ErrDenied) {
		t.Fatalf("admin should not be able to rewrite own allowlist entry, got %v", err)
	}

	posterSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, poster.Agent)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.PostMessage(ctx, poster, PostInput{
		RoomID:             room.RoomID,
		Body:               "hello",
		IdempotencyKey:     "idem-1",
		RequestHash:        "hash-1",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.PostMessage(ctx, poster, PostInput{
		RoomID:             room.RoomID,
		Body:               "hello",
		IdempotencyKey:     "idem-1",
		RequestHash:        "hash-1",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !replay.IdempotentReplay || replay.Message.MessageID != first.Message.MessageID {
		t.Fatalf("unexpected replay: %+v", replay)
	}
	if _, err := s.PostMessage(ctx, poster, PostInput{
		RoomID:             room.RoomID,
		Body:               "changed",
		IdempotencyKey:     "idem-1",
		RequestHash:        "hash-2",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	}); !errors.Is(err, board.ErrConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	ownerSnapshot, err = s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAllowlist(ctx, owner, RevokeInput{
		RoomID:              room.RoomID,
		TargetAgent:         poster.Agent,
		ActorMemberVersion:  ownerSnapshot.Membership.Version,
		ExpectedRoomVersion: ownerSnapshot.Room.Version,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PostMessage(ctx, poster, PostInput{
		RoomID:             room.RoomID,
		Body:               "hello",
		IdempotencyKey:     "idem-1",
		RequestHash:        "hash-1",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	}); !errors.Is(err, board.ErrDenied) {
		t.Fatalf("revoked poster should be denied before idempotent replay, got %v", err)
	}
	rooms, err := s.ListRooms(ctx, poster.Agent, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rooms.Items) != 0 {
		t.Fatalf("revoked poster should not list room: %+v", rooms.Items)
	}
}

func TestMemoryStoreReadMessagesDefaultsToRecentWindow(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	owner := board.Identity{Agent: "owner.example.com"}
	room, err := s.CreateRoom(ctx, owner, CreateRoomInput{RoomID: "room"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < board.MaxLimit+5; i++ {
		_, err := s.PostMessage(ctx, owner, PostInput{
			RoomID:             room.RoomID,
			Body:               "message",
			IdempotencyKey:     fmt.Sprintf("idem-%d", i),
			RequestHash:        fmt.Sprintf("hash-%d", i),
			ActorMemberVersion: snapshot.Membership.Version,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ReadMessages(ctx, room.RoomID, 500, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != board.MaxLimit {
		t.Fatalf("got %d messages, want %d", len(page.Items), board.MaxLimit)
	}
	if page.Items[0].IdempotencyKey != "idem-5" {
		t.Fatalf("first recent message = %q, want idem-5", page.Items[0].IdempotencyKey)
	}
	if page.Items[len(page.Items)-1].IdempotencyKey != "idem-104" {
		t.Fatalf("last recent message = %q, want idem-104", page.Items[len(page.Items)-1].IdempotencyKey)
	}
}

func TestMemoryStoreNicknamesAreRoomScopedUniqueAndReleased(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	owner := board.Identity{Agent: "owner.example.com"}
	poster := board.Identity{Agent: "poster.example.com"}
	reader := board.Identity{Agent: "reader.example.com"}
	room, err := s.CreateRoom(ctx, owner, CreateRoomInput{RoomID: "room"})
	if err != nil {
		t.Fatal(err)
	}
	ownerSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GrantAllowlist(ctx, owner, GrantInput{
		RoomID:              room.RoomID,
		TargetAgent:         poster.Agent,
		Role:                board.RolePoster,
		ActorMemberVersion:  ownerSnapshot.Membership.Version,
		ExpectedRoomVersion: ownerSnapshot.Room.Version,
	}); err != nil {
		t.Fatal(err)
	}
	ownerSnapshot, err = s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GrantAllowlist(ctx, owner, GrantInput{
		RoomID:              room.RoomID,
		TargetAgent:         reader.Agent,
		Role:                board.RoleReader,
		ActorMemberVersion:  ownerSnapshot.Membership.Version,
		ExpectedRoomVersion: ownerSnapshot.Room.Version,
	}); err != nil {
		t.Fatal(err)
	}
	posterSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, poster.Agent)
	if err != nil {
		t.Fatal(err)
	}
	posterMember, err := s.SetNickname(ctx, poster, SetNicknameInput{
		RoomID:             room.RoomID,
		Nickname:           "Wolfgang",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if posterMember.Nickname != "Wolfgang" {
		t.Fatalf("nickname = %q", posterMember.Nickname)
	}
	secondRoom, err := s.CreateRoom(ctx, owner, CreateRoomInput{RoomID: "second-room"})
	if err != nil {
		t.Fatal(err)
	}
	secondRoomOwnerSnapshot, err := s.GetRoomForAgent(ctx, secondRoom.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNickname(ctx, owner, SetNicknameInput{
		RoomID:             secondRoom.RoomID,
		Nickname:           "wolfgang",
		ActorMemberVersion: secondRoomOwnerSnapshot.Membership.Version,
	}); err != nil {
		t.Fatalf("same nickname should be allowed in a different room: %v", err)
	}
	readerSnapshot, err := s.GetRoomForAgent(ctx, room.RoomID, reader.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNickname(ctx, reader, SetNicknameInput{
		RoomID:             room.RoomID,
		Nickname:           "wolfgang",
		ActorMemberVersion: readerSnapshot.Membership.Version,
	}); !errors.Is(err, board.ErrConflict) {
		t.Fatalf("case-insensitive conflict error = %v", err)
	}
	posterSnapshot, err = s.GetRoomForAgent(ctx, room.RoomID, poster.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNickname(ctx, poster, SetNicknameInput{
		RoomID:             room.RoomID,
		Nickname:           "Wolf",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	}); err != nil {
		t.Fatal(err)
	}
	readerSnapshot, err = s.GetRoomForAgent(ctx, room.RoomID, reader.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNickname(ctx, reader, SetNicknameInput{
		RoomID:             room.RoomID,
		Nickname:           "wolfgang",
		ActorMemberVersion: readerSnapshot.Membership.Version,
	}); err != nil {
		t.Fatalf("old nickname should be released after update: %v", err)
	}
	ownerSnapshot, err = s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeAllowlist(ctx, owner, RevokeInput{
		RoomID:              room.RoomID,
		TargetAgent:         reader.Agent,
		ActorMemberVersion:  ownerSnapshot.Membership.Version,
		ExpectedRoomVersion: ownerSnapshot.Room.Version,
	}); err != nil {
		t.Fatal(err)
	}
	posterSnapshot, err = s.GetRoomForAgent(ctx, room.RoomID, poster.Agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetNickname(ctx, poster, SetNicknameInput{
		RoomID:             room.RoomID,
		Nickname:           "wolfgang",
		ActorMemberVersion: posterSnapshot.Membership.Version,
	}); err != nil {
		t.Fatalf("revoked nickname should be released: %v", err)
	}
	if _, err := s.SetNickname(ctx, board.Identity{Agent: "unlisted.example.com"}, SetNicknameInput{
		RoomID:   room.RoomID,
		Nickname: "unlisted",
	}); !errors.Is(err, board.ErrDenied) {
		t.Fatalf("unlisted nickname error = %v", err)
	}
}

func TestMemoryStoreMessagesSnapshotNicknameAndReadAfter(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	owner := board.Identity{Agent: "owner.example.com"}
	room, err := s.CreateRoom(ctx, owner, CreateRoomInput{RoomID: "room"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.GetRoomForAgent(ctx, room.RoomID, owner.Agent)
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.SetNickname(ctx, owner, SetNicknameInput{
		RoomID:             room.RoomID,
		Nickname:           "owner",
		ActorMemberVersion: snapshot.Membership.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.PostMessage(ctx, owner, PostInput{
		RoomID:             room.RoomID,
		Body:               "first",
		AuthorNickname:     member.Nickname,
		IdempotencyKey:     "idem-1",
		RequestHash:        "hash-1",
		ActorMemberVersion: member.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.PostMessage(ctx, owner, PostInput{
		RoomID:             room.RoomID,
		Body:               "second",
		AuthorNickname:     member.Nickname,
		IdempotencyKey:     "idem-2",
		RequestHash:        "hash-2",
		ActorMemberVersion: member.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.ReadMessages(ctx, room.RoomID, 25, "", first.Message.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].MessageID != second.Message.MessageID {
		t.Fatalf("after page = %+v", page.Items)
	}
	if page.Items[0].AuthorNickname != "owner" {
		t.Fatalf("author nickname = %q", page.Items[0].AuthorNickname)
	}
	page, err = s.ReadMessages(ctx, room.RoomID, 25, "", "msg_00000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].MessageID != first.Message.MessageID {
		t.Fatalf("older unknown after page = %+v", page.Items)
	}
	page, err = s.ReadMessages(ctx, room.RoomID, 25, "", "msg_zzzzzzzzzzzzzzzzzzzzzzzzzz")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("newer unknown after page = %+v", page.Items)
	}
}

func TestTranslateDDBWriteErrorClassifiesTransactionReasons(t *testing.T) {
	conditional := &ddbtypes.TransactionCanceledException{
		CancellationReasons: []ddbtypes.CancellationReason{
			{Code: aws.String("None")},
			{Code: aws.String("ConditionalCheckFailed")},
		},
	}
	if err := translateDDBWriteError(conditional); !errors.Is(err, board.ErrConflict) {
		t.Fatalf("conditional transaction error = %v, want conflict", err)
	}
	throttled := &ddbtypes.TransactionCanceledException{
		CancellationReasons: []ddbtypes.CancellationReason{{Code: aws.String("ProvisionedThroughputExceeded")}},
	}
	if err := translateDDBWriteError(throttled); !errors.Is(err, board.ErrDependency) {
		t.Fatalf("throttled transaction error = %v, want dependency", err)
	}
	unknown := &ddbtypes.TransactionCanceledException{}
	if err := translateDDBWriteError(unknown); !errors.Is(err, board.ErrDependency) {
		t.Fatalf("reasonless transaction error = %v, want dependency", err)
	}
}

func TestDynamoDBRoomItemPersistsArchivedFalse(t *testing.T) {
	attrs, err := attributevalue.MarshalMap(ddbItem{
		PK:            "ROOM#room",
		SK:            "META",
		Type:          "room",
		SchemaVersion: board.SchemaVersion,
		Archived:      false,
	})
	if err != nil {
		t.Fatal(err)
	}
	value, ok := attrs["archived"].(*ddbtypes.AttributeValueMemberBOOL)
	if !ok {
		t.Fatalf("archived=false must be present as BOOL, got %#v", attrs["archived"])
	}
	if value.Value {
		t.Fatal("archived should be false")
	}
}

func TestDynamoDBNicknameTransactionsUseSafeConditions(t *testing.T) {
	member := ddbItem{Version: 7, NicknameKey: "wolfgang"}
	condition := revokeMemberCondition(member.NicknameKey)
	if !strings.Contains(condition, "#version = :targetVersion") || !strings.Contains(condition, "#nicknameKey = :nicknameKey") {
		t.Fatalf("revoke condition does not pin version and nickname: %s", condition)
	}
	values := revokeMemberValues(member)
	if got := values[":targetVersion"].(*ddbtypes.AttributeValueMemberN).Value; got != "7" {
		t.Fatalf("target version = %s", got)
	}
	if got := values[":nicknameKey"].(*ddbtypes.AttributeValueMemberS).Value; got != "wolfgang" {
		t.Fatalf("nickname key = %s", got)
	}
	emptyCondition := revokeMemberCondition("")
	if !strings.Contains(emptyCondition, "attribute_not_exists(#nicknameKey)") {
		t.Fatalf("empty nickname condition should reject concurrent claims: %s", emptyCondition)
	}
	put := putNicknameTxn("table", "room", "roomKey", "Wolfgang", "wolfgang", "agent.example.com", "now").Put
	if got := *put.ConditionExpression; !strings.Contains(got, "#agent = :agent") {
		t.Fatalf("nickname put condition should alias reserved agent name: %s", got)
	}
}
