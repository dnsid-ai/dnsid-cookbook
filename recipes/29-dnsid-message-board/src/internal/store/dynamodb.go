package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
	"github.com/oklog/ulid/v2"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/validation"
)

type DynamoDBStore struct {
	client            *dynamodb.Client
	tableName         string
	now               func() time.Time
	MaxRoomsPerAgent  int64
	MaxMembersPerRoom int64
}

func NewDynamoDBStore(client *dynamodb.Client, tableName string) *DynamoDBStore {
	return &DynamoDBStore{
		client:            client,
		tableName:         tableName,
		now:               time.Now,
		MaxRoomsPerAgent:  50,
		MaxMembersPerRoom: 100,
	}
}

type ddbItem struct {
	PK             string             `dynamodbav:"PK"`
	SK             string             `dynamodbav:"SK"`
	Type           string             `dynamodbav:"type"`
	SchemaVersion  int                `dynamodbav:"schemaVersion"`
	RoomID         string             `dynamodbav:"roomId,omitempty"`
	RoomKey        string             `dynamodbav:"roomKey,omitempty"`
	Name           string             `dynamodbav:"name,omitempty"`
	Description    string             `dynamodbav:"description,omitempty"`
	Owner          string             `dynamodbav:"owner,omitempty"`
	Agent          string             `dynamodbav:"agent,omitempty"`
	Role           board.Role         `dynamodbav:"role,omitempty"`
	Capabilities   []board.Capability `dynamodbav:"capabilities,omitempty"`
	Author         string             `dynamodbav:"author,omitempty"`
	Nickname       string             `dynamodbav:"nickname,omitempty"`
	NicknameKey    string             `dynamodbav:"nicknameKey,omitempty"`
	AuthorNickname string             `dynamodbav:"authorNickname,omitempty"`
	Body           string             `dynamodbav:"body,omitempty"`
	MessageID      string             `dynamodbav:"messageId,omitempty"`
	IdempotencyKey string             `dynamodbav:"idempotencyKey,omitempty"`
	RequestHash    string             `dynamodbav:"requestHash,omitempty"`
	StatusCode     int                `dynamodbav:"statusCode,omitempty"`
	EventType      string             `dynamodbav:"eventType,omitempty"`
	Actor          string             `dynamodbav:"actor,omitempty"`
	TargetAgent    string             `dynamodbav:"targetAgent,omitempty"`
	TokenJTIHash   string             `dynamodbav:"tokenJtiHash,omitempty"`
	CreatedBy      string             `dynamodbav:"createdBy,omitempty"`
	UpdatedBy      string             `dynamodbav:"updatedBy,omitempty"`
	CreatedAt      string             `dynamodbav:"createdAt,omitempty"`
	UpdatedAt      string             `dynamodbav:"updatedAt,omitempty"`
	Version        int64              `dynamodbav:"version,omitempty"`
	Archived       bool               `dynamodbav:"archived"`
	MemberCount    int64              `dynamodbav:"memberCount,omitempty"`
	RoomCount      int64              `dynamodbav:"roomCount,omitempty"`
	GSI1PK         string             `dynamodbav:"GSI1PK,omitempty"`
	GSI1SK         string             `dynamodbav:"GSI1SK,omitempty"`
}

func (s *DynamoDBStore) CreateRoom(ctx context.Context, actor board.Identity, input CreateRoomInput) (board.Room, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.Room{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, err := validation.RoomKey(roomID)
	if err != nil {
		return board.Room{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	now := s.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	name := input.Name
	if name == "" {
		name = roomID
	}
	capabilities, _ := board.CapabilitiesForRole(board.RoleOwner)
	roomItem := ddbItem{
		PK:            roomPK(roomKey),
		SK:            "META",
		Type:          "room",
		SchemaVersion: board.SchemaVersion,
		RoomID:        roomID,
		RoomKey:       roomKey,
		Name:          name,
		Description:   input.Description,
		Owner:         actor.Agent,
		CreatedAt:     nowText,
		UpdatedAt:     nowText,
		Version:       1,
		Archived:      false,
		MemberCount:   1,
	}
	memberItem := ddbItem{
		PK:            roomPK(roomKey),
		SK:            memberSK(actor.Agent),
		Type:          "membership",
		SchemaVersion: board.SchemaVersion,
		RoomID:        roomID,
		RoomKey:       roomKey,
		Agent:         actor.Agent,
		Role:          board.RoleOwner,
		Capabilities:  capabilities,
		CreatedBy:     actor.Agent,
		UpdatedBy:     actor.Agent,
		CreatedAt:     nowText,
		UpdatedAt:     nowText,
		Version:       1,
		GSI1PK:        agentPK(actor.Agent),
		GSI1SK:        "ROOM#" + nowText + "#" + roomKey,
	}
	auditItem := auditItem(roomKey, "room_created", actor.Agent, actor.Agent, board.RoleOwner, input.TokenJTIHash, nowText)
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []ddbtypes.TransactWriteItem{
		putItemTxn(s.tableName, roomItem, "attribute_not_exists(PK)"),
		putItemTxn(s.tableName, memberItem, "attribute_not_exists(PK)"),
		putItemTxn(s.tableName, auditItem, "attribute_not_exists(PK)"),
		{
			Update: &ddbtypes.Update{
				TableName:                aws.String(s.tableName),
				Key:                      key(agentPK(actor.Agent), "QUOTA"),
				UpdateExpression:         aws.String("SET #type = :type, schemaVersion = :schemaVersion, roomCount = if_not_exists(roomCount, :zero) + :one, updatedAt = :updatedAt"),
				ConditionExpression:      aws.String("attribute_not_exists(roomCount) OR roomCount < :maxRooms"),
				ExpressionAttributeNames: map[string]string{"#type": "type"},
				ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
					":type":          &ddbtypes.AttributeValueMemberS{Value: "agent_quota"},
					":schemaVersion": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(board.SchemaVersion)},
					":zero":          &ddbtypes.AttributeValueMemberN{Value: "0"},
					":one":           &ddbtypes.AttributeValueMemberN{Value: "1"},
					":maxRooms":      &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(s.MaxRoomsPerAgent)},
					":updatedAt":     &ddbtypes.AttributeValueMemberS{Value: nowText},
				},
			},
		},
	}})
	if err != nil {
		return board.Room{}, translateDDBWriteError(err)
	}
	return roomFromItem(roomItem), nil
}

func (s *DynamoDBStore) ListRooms(ctx context.Context, agent string, limit int, cursor string) (board.Page[board.RoomSummary], error) {
	limit = board.BoundLimit(limit, board.DefaultListLimit)
	start, err := decodeDDBCursor(cursor)
	if err != nil {
		return board.Page[board.RoomSummary]{}, fmt.Errorf("%w: invalid cursor", board.ErrValidation)
	}
	out, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(s.tableName),
		IndexName:                 aws.String("GSI1"),
		KeyConditionExpression:    aws.String("GSI1PK = :agent"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":agent": &ddbtypes.AttributeValueMemberS{Value: agentPK(agent)}},
		ExclusiveStartKey:         start,
		Limit:                     aws.Int32(int32(limit)),
		ScanIndexForward:          aws.Bool(false),
	})
	if err != nil {
		return board.Page[board.RoomSummary]{}, translateDDBError(err)
	}
	var summaries []board.RoomSummary
	for _, item := range out.Items {
		var member ddbItem
		if err := attributevalue.UnmarshalMap(item, &member); err != nil {
			return board.Page[board.RoomSummary]{}, err
		}
		snapshot, err := s.GetRoomForAgent(ctx, member.RoomID, agent)
		if errors.Is(err, board.ErrNotFound) || snapshot.Membership == nil {
			continue
		}
		if err != nil {
			return board.Page[board.RoomSummary]{}, err
		}
		summaries = append(summaries, board.RoomSummary{
			RoomID:       snapshot.Room.RoomID,
			Name:         snapshot.Room.Name,
			Description:  snapshot.Room.Description,
			Owner:        snapshot.Room.Owner,
			Role:         snapshot.Membership.Role,
			Capabilities: snapshot.Membership.Capabilities,
			UpdatedAt:    snapshot.Room.UpdatedAt,
		})
	}
	return board.Page[board.RoomSummary]{Items: summaries, NextCursor: encodeDDBCursor(out.LastEvaluatedKey)}, nil
}

func (s *DynamoDBStore) GetRoomForAgent(ctx context.Context, roomID string, agent string) (board.AuthSnapshot, error) {
	roomID, err := validation.NormalizeRoomID(roomID)
	if err != nil {
		return board.AuthSnapshot{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, err := validation.RoomKey(roomID)
	if err != nil {
		return board.AuthSnapshot{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomItem, err := s.getItem(ctx, roomPK(roomKey), "META")
	if err != nil {
		return board.AuthSnapshot{}, err
	}
	snapshot := board.AuthSnapshot{Room: roomFromItem(roomItem)}
	memberItem, err := s.getItem(ctx, roomPK(roomKey), memberSK(agent))
	if errors.Is(err, board.ErrNotFound) {
		return snapshot, nil
	}
	if err != nil {
		return board.AuthSnapshot{}, err
	}
	member := membershipFromItem(memberItem)
	snapshot.Membership = &member
	return snapshot, nil
}

func (s *DynamoDBStore) ListAllowlist(ctx context.Context, roomID string, limit int, cursor string) (board.Page[board.Membership], error) {
	limit = board.BoundLimit(limit, board.DefaultListLimit)
	roomID, err := validation.NormalizeRoomID(roomID)
	if err != nil {
		return board.Page[board.Membership]{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, err := validation.RoomKey(roomID)
	if err != nil {
		return board.Page[board.Membership]{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	start, err := decodeDDBCursor(cursor)
	if err != nil {
		return board.Page[board.Membership]{}, fmt.Errorf("%w: invalid cursor", board.ErrValidation)
	}
	out, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("PK = :pk AND begins_with(SK, :memberPrefix)"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":pk":           &ddbtypes.AttributeValueMemberS{Value: roomPK(roomKey)},
			":memberPrefix": &ddbtypes.AttributeValueMemberS{Value: "MEMBER#"},
		},
		ExclusiveStartKey: start,
		Limit:             aws.Int32(int32(limit)),
	})
	if err != nil {
		return board.Page[board.Membership]{}, translateDDBError(err)
	}
	entries := make([]board.Membership, 0, len(out.Items))
	for _, raw := range out.Items {
		var item ddbItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return board.Page[board.Membership]{}, err
		}
		entries = append(entries, membershipFromItem(item))
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
	return board.Page[board.Membership]{Items: entries, NextCursor: encodeDDBCursor(out.LastEvaluatedKey)}, nil
}

func (s *DynamoDBStore) GrantAllowlist(ctx context.Context, actor board.Identity, input GrantInput) (board.Membership, bool, error) {
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
	roomKey, _ := validation.RoomKey(roomID)
	roomItem, err := s.getItem(ctx, roomPK(roomKey), "META")
	if err != nil {
		return board.Membership{}, false, err
	}
	if target == actor.Agent {
		return board.Membership{}, false, board.ErrDenied
	}
	if target == roomItem.Owner {
		return board.Membership{}, false, board.ErrDenied
	}
	existing, err := s.getItem(ctx, roomPK(roomKey), memberSK(target))
	created := errors.Is(err, board.ErrNotFound)
	if err != nil && !created {
		return board.Membership{}, false, err
	}
	if !created && existing.Role == input.Role {
		if err := s.guardAllowlistAuthorization(ctx, actor, roomKey, input.ActorMemberVersion, input.ExpectedRoomVersion); err != nil {
			return board.Membership{}, false, err
		}
		return membershipFromItem(existing), false, nil
	}
	nowText := s.now().UTC().Format(time.RFC3339Nano)
	member := ddbItem{
		PK:            roomPK(roomKey),
		SK:            memberSK(target),
		Type:          "membership",
		SchemaVersion: board.SchemaVersion,
		RoomID:        roomID,
		RoomKey:       roomKey,
		Agent:         target,
		Role:          input.Role,
		Capabilities:  capabilities,
		CreatedBy:     actor.Agent,
		UpdatedBy:     actor.Agent,
		CreatedAt:     nowText,
		UpdatedAt:     nowText,
		Version:       1,
		GSI1PK:        agentPK(target),
		GSI1SK:        "ROOM#" + nowText + "#" + roomKey,
	}
	if !created {
		member.Nickname = existing.Nickname
		member.NicknameKey = existing.NicknameKey
		member.CreatedBy = existing.CreatedBy
		member.CreatedAt = existing.CreatedAt
		member.Version = existing.Version + 1
	}
	roomUpdate := "SET #version = #version + :one, updatedAt = :updatedAt"
	if created {
		roomUpdate += ", memberCount = memberCount + :one"
	}
	items := []ddbtypes.TransactWriteItem{
		actorConditionTxn(s.tableName, roomKey, actor.Agent, input.ActorMemberVersion, board.ActionUpdateAllowList),
		{
			Update: &ddbtypes.Update{
				TableName:                aws.String(s.tableName),
				Key:                      key(roomPK(roomKey), "META"),
				UpdateExpression:         aws.String(roomUpdate),
				ConditionExpression:      aws.String("#archived = :false AND #version = :expectedVersion" + memberLimitCondition(created)),
				ExpressionAttributeNames: map[string]string{"#version": "version", "#archived": "archived"},
				ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
					":false":           &ddbtypes.AttributeValueMemberBOOL{Value: false},
					":one":             &ddbtypes.AttributeValueMemberN{Value: "1"},
					":updatedAt":       &ddbtypes.AttributeValueMemberS{Value: nowText},
					":expectedVersion": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(input.ExpectedRoomVersion)},
					":maxMembers":      &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(s.MaxMembersPerRoom)},
				},
			},
		},
		putOrUpdateMembershipTxn(s.tableName, member, created),
		putItemTxn(s.tableName, auditItem(roomKey, "allowlist_granted", actor.Agent, target, input.Role, input.TokenJTIHash, nowText), "attribute_not_exists(PK)"),
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		return board.Membership{}, false, translateDDBWriteError(err)
	}
	return membershipFromItem(member), created, nil
}

func (s *DynamoDBStore) RevokeAllowlist(ctx context.Context, actor board.Identity, input RevokeInput) (bool, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	target, err := validation.CanonicalDNSName(input.TargetAgent)
	if err != nil {
		return false, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, _ := validation.RoomKey(roomID)
	roomItem, err := s.getItem(ctx, roomPK(roomKey), "META")
	if err != nil {
		return false, err
	}
	if target == actor.Agent {
		return false, board.ErrDenied
	}
	if target == roomItem.Owner {
		return false, board.ErrDenied
	}
	targetMember, err := s.getItem(ctx, roomPK(roomKey), memberSK(target))
	if err != nil {
		return false, err
	}
	nowText := s.now().UTC().Format(time.RFC3339Nano)
	items := []ddbtypes.TransactWriteItem{
		actorConditionTxn(s.tableName, roomKey, actor.Agent, input.ActorMemberVersion, board.ActionUpdateAllowList),
		{
			Delete: &ddbtypes.Delete{
				TableName:                 aws.String(s.tableName),
				Key:                       key(roomPK(roomKey), memberSK(target)),
				ConditionExpression:       aws.String(revokeMemberCondition(targetMember.NicknameKey)),
				ExpressionAttributeNames:  revokeMemberNames(),
				ExpressionAttributeValues: revokeMemberValues(targetMember),
			},
		},
		{
			Update: &ddbtypes.Update{
				TableName:                aws.String(s.tableName),
				Key:                      key(roomPK(roomKey), "META"),
				UpdateExpression:         aws.String("SET #version = #version + :one, updatedAt = :updatedAt, memberCount = memberCount - :one"),
				ConditionExpression:      aws.String("#archived = :false AND #version = :expectedVersion"),
				ExpressionAttributeNames: map[string]string{"#version": "version", "#archived": "archived"},
				ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
					":false":           &ddbtypes.AttributeValueMemberBOOL{Value: false},
					":one":             &ddbtypes.AttributeValueMemberN{Value: "1"},
					":updatedAt":       &ddbtypes.AttributeValueMemberS{Value: nowText},
					":expectedVersion": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(input.ExpectedRoomVersion)},
				},
			},
		},
		putItemTxn(s.tableName, auditItem(roomKey, "allowlist_revoked", actor.Agent, target, "", input.TokenJTIHash, nowText), "attribute_not_exists(PK)"),
	}
	if targetMember.NicknameKey != "" {
		items = append(items, deleteNicknameTxn(s.tableName, roomKey, targetMember.NicknameKey, target))
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		return false, translateDDBWriteError(err)
	}
	return true, nil
}

func (s *DynamoDBStore) SetNickname(ctx context.Context, actor board.Identity, input SetNicknameInput) (board.Membership, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.Membership{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	nickname, nicknameKey, err := validation.Nickname(input.Nickname)
	if err != nil {
		return board.Membership{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, _ := validation.RoomKey(roomID)
	member, err := s.getItem(ctx, roomPK(roomKey), memberSK(actor.Agent))
	if errors.Is(err, board.ErrNotFound) {
		return board.Membership{}, board.ErrDenied
	}
	if err != nil {
		return board.Membership{}, err
	}
	if !board.RoleCan(member.Role, board.ActionUpdateNickname) {
		return board.Membership{}, board.ErrDenied
	}
	if member.Nickname == nickname && member.NicknameKey == nicknameKey {
		if err := s.guardMembershipAction(ctx, roomKey, actor.Agent, input.ActorMemberVersion, board.ActionUpdateNickname); err != nil {
			return board.Membership{}, err
		}
		return membershipFromItem(member), nil
	}
	nowText := s.now().UTC().Format(time.RFC3339Nano)
	items := []ddbtypes.TransactWriteItem{
		roomOpenConditionTxn(s.tableName, roomKey),
		updateNicknameMembershipTxn(s.tableName, roomKey, actor.Agent, input.ActorMemberVersion, member.Role, nickname, nicknameKey, nowText),
	}
	if member.NicknameKey != "" && member.NicknameKey != nicknameKey {
		items = append(items, deleteNicknameTxn(s.tableName, roomKey, member.NicknameKey, actor.Agent))
	}
	if member.NicknameKey != nicknameKey {
		items = append(items, putNicknameTxn(s.tableName, roomID, roomKey, nickname, nicknameKey, actor.Agent, nowText))
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: items})
	if err != nil {
		return board.Membership{}, translateDDBWriteError(err)
	}
	member.Nickname = nickname
	member.NicknameKey = nicknameKey
	member.UpdatedBy = actor.Agent
	member.UpdatedAt = nowText
	member.Version++
	return membershipFromItem(member), nil
}

func (s *DynamoDBStore) PostMessage(ctx context.Context, actor board.Identity, input PostInput) (board.PostResult, error) {
	roomID, err := validation.NormalizeRoomID(input.RoomID)
	if err != nil {
		return board.PostResult{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	if input.IdempotencyKey == "" {
		return board.PostResult{}, fmt.Errorf("%w: idempotency key is required", board.ErrValidation)
	}
	roomKey, _ := validation.RoomKey(roomID)
	idemSK := "IDEMP#" + actor.Agent + "#" + input.IdempotencyKey
	idem, err := s.getItem(ctx, roomPK(roomKey), idemSK)
	if err == nil {
		return s.replayPost(ctx, actor, input, roomKey, idem)
	}
	if err != nil && !errors.Is(err, board.ErrNotFound) {
		return board.PostResult{}, err
	}
	nowText := s.now().UTC().Format(time.RFC3339Nano)
	messageID := "msg_" + ulid.Make().String()
	message := ddbItem{
		PK:             roomPK(roomKey),
		SK:             "MSG#" + messageID,
		Type:           "message",
		SchemaVersion:  board.SchemaVersion,
		RoomID:         roomID,
		RoomKey:        roomKey,
		MessageID:      messageID,
		Author:         actor.Agent,
		AuthorNickname: input.AuthorNickname,
		Body:           input.Body,
		CreatedAt:      nowText,
		IdempotencyKey: input.IdempotencyKey,
		RequestHash:    input.RequestHash,
	}
	idempotency := ddbItem{
		PK:            roomPK(roomKey),
		SK:            idemSK,
		Type:          "idempotency",
		SchemaVersion: board.SchemaVersion,
		MessageID:     messageID,
		RequestHash:   input.RequestHash,
		StatusCode:    201,
		CreatedAt:     nowText,
	}
	_, err = s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []ddbtypes.TransactWriteItem{
		roomOpenConditionTxn(s.tableName, roomKey),
		actorConditionTxn(s.tableName, roomKey, actor.Agent, input.ActorMemberVersion, board.ActionPostMessage),
		putItemTxn(s.tableName, idempotency, "attribute_not_exists(PK)"),
		putItemTxn(s.tableName, message, "attribute_not_exists(PK)"),
	}})
	if err != nil {
		writeErr := translateDDBWriteError(err)
		if errors.Is(writeErr, board.ErrConflict) {
			idem, replayErr := s.getItem(ctx, roomPK(roomKey), idemSK)
			if replayErr == nil {
				return s.replayPost(ctx, actor, input, roomKey, idem)
			}
			if replayErr != nil && !errors.Is(replayErr, board.ErrNotFound) {
				return board.PostResult{}, replayErr
			}
			if authErr := s.classifyPostConditionConflict(ctx, actor, roomKey, input.ActorMemberVersion); authErr != nil {
				return board.PostResult{}, authErr
			}
		}
		return board.PostResult{}, writeErr
	}
	return board.PostResult{Message: messageFromItem(message)}, nil
}

func (s *DynamoDBStore) classifyPostConditionConflict(ctx context.Context, actor board.Identity, roomKey string, actorMemberVersion int64) error {
	room, err := s.getItem(ctx, roomPK(roomKey), "META")
	if errors.Is(err, board.ErrNotFound) {
		return board.ErrDenied
	}
	if err != nil {
		return err
	}
	if room.Archived {
		return board.ErrDenied
	}
	member, err := s.getItem(ctx, roomPK(roomKey), memberSK(actor.Agent))
	if errors.Is(err, board.ErrNotFound) {
		return board.ErrDenied
	}
	if err != nil {
		return err
	}
	if actorMemberVersion != 0 && member.Version != actorMemberVersion {
		return board.ErrConflict
	}
	if !board.RoleCan(member.Role, board.ActionPostMessage) {
		return board.ErrDenied
	}
	return board.ErrConflict
}

func (s *DynamoDBStore) replayPost(ctx context.Context, actor board.Identity, input PostInput, roomKey string, idem ddbItem) (board.PostResult, error) {
	if err := s.guardPostAuthorization(ctx, actor, roomKey, input.ActorMemberVersion); err != nil {
		if errors.Is(err, board.ErrConflict) {
			if authErr := s.classifyPostConditionConflict(ctx, actor, roomKey, input.ActorMemberVersion); authErr != nil {
				return board.PostResult{}, authErr
			}
		}
		return board.PostResult{}, err
	}
	if idem.RequestHash != input.RequestHash {
		return board.PostResult{IdempotencyConflict: true}, board.ErrConflict
	}
	msg, err := s.getItem(ctx, roomPK(roomKey), "MSG#"+idem.MessageID)
	if err != nil {
		return board.PostResult{}, err
	}
	return board.PostResult{Message: messageFromItem(msg), IdempotentReplay: true}, nil
}

func (s *DynamoDBStore) guardPostAuthorization(ctx context.Context, actor board.Identity, roomKey string, actorMemberVersion int64) error {
	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []ddbtypes.TransactWriteItem{
		roomOpenConditionTxn(s.tableName, roomKey),
		actorConditionTxn(s.tableName, roomKey, actor.Agent, actorMemberVersion, board.ActionPostMessage),
	}})
	if err != nil {
		return translateDDBWriteError(err)
	}
	return nil
}

func (s *DynamoDBStore) guardAllowlistAuthorization(ctx context.Context, actor board.Identity, roomKey string, actorMemberVersion int64, expectedRoomVersion int64) error {
	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []ddbtypes.TransactWriteItem{
		roomVersionConditionTxn(s.tableName, roomKey, expectedRoomVersion),
		actorConditionTxn(s.tableName, roomKey, actor.Agent, actorMemberVersion, board.ActionUpdateAllowList),
	}})
	if err != nil {
		return translateDDBWriteError(err)
	}
	return nil
}

func (s *DynamoDBStore) guardMembershipAction(ctx context.Context, roomKey string, agent string, actorMemberVersion int64, action board.Action) error {
	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []ddbtypes.TransactWriteItem{
		roomOpenConditionTxn(s.tableName, roomKey),
		actorConditionTxn(s.tableName, roomKey, agent, actorMemberVersion, action),
	}})
	if err != nil {
		return translateDDBWriteError(err)
	}
	return nil
}

func (s *DynamoDBStore) ReadMessages(ctx context.Context, roomID string, limit int, cursor string, after string) (board.Page[board.Message], error) {
	limit = board.BoundLimit(limit, board.DefaultMessagesLimit)
	roomID, err := validation.NormalizeRoomID(roomID)
	if err != nil {
		return board.Page[board.Message]{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	roomKey, err := validation.RoomKey(roomID)
	if err != nil {
		return board.Page[board.Message]{}, fmt.Errorf("%w: %v", board.ErrValidation, err)
	}
	start, err := decodeDDBCursor(cursor)
	if err != nil {
		return board.Page[board.Message]{}, fmt.Errorf("%w: invalid cursor", board.ErrValidation)
	}
	query := &dynamodb.QueryInput{
		TableName:         aws.String(s.tableName),
		ExclusiveStartKey: start,
		Limit:             aws.Int32(int32(limit)),
	}
	if after != "" {
		query.KeyConditionExpression = aws.String("PK = :pk AND SK BETWEEN :after AND :end")
		query.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{
			":pk":    &ddbtypes.AttributeValueMemberS{Value: roomPK(roomKey)},
			":after": &ddbtypes.AttributeValueMemberS{Value: "MSG#" + after + "\x00"},
			":end":   &ddbtypes.AttributeValueMemberS{Value: "MSG$"},
		}
		query.ScanIndexForward = aws.Bool(true)
	} else {
		query.KeyConditionExpression = aws.String("PK = :pk AND SK BETWEEN :start AND :end")
		query.ExpressionAttributeValues = map[string]ddbtypes.AttributeValue{
			":pk":    &ddbtypes.AttributeValueMemberS{Value: roomPK(roomKey)},
			":start": &ddbtypes.AttributeValueMemberS{Value: "MSG#"},
			":end":   &ddbtypes.AttributeValueMemberS{Value: "MSG$"},
		}
		query.ScanIndexForward = aws.Bool(false)
	}
	out, err := s.client.Query(ctx, query)
	if err != nil {
		return board.Page[board.Message]{}, translateDDBError(err)
	}
	messages := make([]board.Message, 0, len(out.Items))
	for _, raw := range out.Items {
		var item ddbItem
		if err := attributevalue.UnmarshalMap(raw, &item); err != nil {
			return board.Page[board.Message]{}, err
		}
		messages = append(messages, messageFromItem(item))
	}
	if after == "" {
		for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
			messages[i], messages[j] = messages[j], messages[i]
		}
	}
	return board.Page[board.Message]{Items: messages, NextCursor: encodeDDBCursor(out.LastEvaluatedKey)}, nil
}

func (s *DynamoDBStore) getItem(ctx context.Context, pk string, sk string) (ddbItem, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      aws.String(s.tableName),
		Key:            key(pk, sk),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return ddbItem{}, translateDDBError(err)
	}
	if len(out.Item) == 0 {
		return ddbItem{}, board.ErrNotFound
	}
	var item ddbItem
	if err := attributevalue.UnmarshalMap(out.Item, &item); err != nil {
		return ddbItem{}, err
	}
	return item, nil
}

func putItemTxn(tableName string, item ddbItem, condition string) ddbtypes.TransactWriteItem {
	attrs, err := attributevalue.MarshalMap(item)
	if err != nil {
		panic(err)
	}
	put := &ddbtypes.Put{TableName: aws.String(tableName), Item: attrs}
	if condition != "" {
		put.ConditionExpression = aws.String(condition)
	}
	return ddbtypes.TransactWriteItem{Put: put}
}

func putOrUpdateMembershipTxn(tableName string, item ddbItem, created bool) ddbtypes.TransactWriteItem {
	if created {
		return putItemTxn(tableName, item, "attribute_not_exists(PK)")
	}
	return ddbtypes.TransactWriteItem{Update: &ddbtypes.Update{
		TableName:                aws.String(tableName),
		Key:                      key(item.PK, item.SK),
		UpdateExpression:         aws.String("SET #role = :role, capabilities = :capabilities, updatedBy = :updatedBy, updatedAt = :updatedAt, #version = #version + :one, GSI1PK = :gsi1pk, GSI1SK = :gsi1sk"),
		ConditionExpression:      aws.String("attribute_exists(PK) AND #role <> :owner"),
		ExpressionAttributeNames: map[string]string{"#role": "role", "#version": "version"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":role":         &ddbtypes.AttributeValueMemberS{Value: string(item.Role)},
			":capabilities": marshalAttribute(item.Capabilities),
			":updatedBy":    &ddbtypes.AttributeValueMemberS{Value: item.UpdatedBy},
			":updatedAt":    &ddbtypes.AttributeValueMemberS{Value: item.UpdatedAt},
			":one":          &ddbtypes.AttributeValueMemberN{Value: "1"},
			":owner":        &ddbtypes.AttributeValueMemberS{Value: string(board.RoleOwner)},
			":gsi1pk":       &ddbtypes.AttributeValueMemberS{Value: item.GSI1PK},
			":gsi1sk":       &ddbtypes.AttributeValueMemberS{Value: item.GSI1SK},
		},
	}}
}

func updateNicknameMembershipTxn(tableName string, roomKey string, agent string, version int64, role board.Role, nickname string, nicknameKey string, nowText string) ddbtypes.TransactWriteItem {
	values := map[string]ddbtypes.AttributeValue{
		":version":     &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(version)},
		":nickname":    &ddbtypes.AttributeValueMemberS{Value: nickname},
		":nicknameKey": &ddbtypes.AttributeValueMemberS{Value: nicknameKey},
		":updatedBy":   &ddbtypes.AttributeValueMemberS{Value: agent},
		":updatedAt":   &ddbtypes.AttributeValueMemberS{Value: nowText},
		":one":         &ddbtypes.AttributeValueMemberN{Value: "1"},
		":role":        &ddbtypes.AttributeValueMemberS{Value: string(role)},
	}
	return ddbtypes.TransactWriteItem{Update: &ddbtypes.Update{
		TableName:                 aws.String(tableName),
		Key:                       key(roomPK(roomKey), memberSK(agent)),
		UpdateExpression:          aws.String("SET nickname = :nickname, nicknameKey = :nicknameKey, updatedBy = :updatedBy, updatedAt = :updatedAt, #version = #version + :one"),
		ConditionExpression:       aws.String("attribute_exists(PK) AND #version = :version AND #role = :role"),
		ExpressionAttributeNames:  map[string]string{"#version": "version", "#role": "role"},
		ExpressionAttributeValues: values,
	}}
}

func putNicknameTxn(tableName string, roomID string, roomKey string, nickname string, nicknameKey string, agent string, nowText string) ddbtypes.TransactWriteItem {
	item := ddbItem{
		PK:            roomPK(roomKey),
		SK:            nicknameSK(nicknameKey),
		Type:          "nickname",
		SchemaVersion: board.SchemaVersion,
		RoomID:        roomID,
		RoomKey:       roomKey,
		Agent:         agent,
		Nickname:      nickname,
		NicknameKey:   nicknameKey,
		CreatedAt:     nowText,
		UpdatedAt:     nowText,
	}
	attrs, err := attributevalue.MarshalMap(item)
	if err != nil {
		panic(err)
	}
	return ddbtypes.TransactWriteItem{Put: &ddbtypes.Put{
		TableName:                aws.String(tableName),
		Item:                     attrs,
		ConditionExpression:      aws.String("attribute_not_exists(PK) OR #agent = :agent"),
		ExpressionAttributeNames: map[string]string{"#agent": "agent"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":agent": &ddbtypes.AttributeValueMemberS{Value: agent},
		},
	}}
}

func deleteNicknameTxn(tableName string, roomKey string, nicknameKey string, agent string) ddbtypes.TransactWriteItem {
	return ddbtypes.TransactWriteItem{Delete: &ddbtypes.Delete{
		TableName:                aws.String(tableName),
		Key:                      key(roomPK(roomKey), nicknameSK(nicknameKey)),
		ConditionExpression:      aws.String("#agent = :agent"),
		ExpressionAttributeNames: map[string]string{"#agent": "agent"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":agent": &ddbtypes.AttributeValueMemberS{Value: agent},
		},
	}}
}

func revokeMemberCondition(nicknameKey string) string {
	condition := "attribute_exists(PK) AND #role <> :owner AND #version = :targetVersion"
	if nicknameKey == "" {
		return condition + " AND attribute_not_exists(#nicknameKey)"
	}
	return condition + " AND #nicknameKey = :nicknameKey"
}

func revokeMemberNames() map[string]string {
	names := map[string]string{"#role": "role", "#version": "version"}
	names["#nicknameKey"] = "nicknameKey"
	return names
}

func revokeMemberValues(member ddbItem) map[string]ddbtypes.AttributeValue {
	values := map[string]ddbtypes.AttributeValue{
		":owner":         &ddbtypes.AttributeValueMemberS{Value: string(board.RoleOwner)},
		":targetVersion": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(member.Version)},
	}
	if member.NicknameKey != "" {
		values[":nicknameKey"] = &ddbtypes.AttributeValueMemberS{Value: member.NicknameKey}
	}
	return values
}

func actorConditionTxn(tableName string, roomKey string, agent string, version int64, action board.Action) ddbtypes.TransactWriteItem {
	roles := []string{string(board.RoleOwner)}
	switch action {
	case board.ActionPostMessage:
		roles = append(roles, string(board.RoleAdmin), string(board.RolePoster))
	case board.ActionUpdateAllowList:
		roles = append(roles, string(board.RoleAdmin))
	case board.ActionUpdateNickname:
		roles = append(roles, string(board.RoleAdmin), string(board.RolePoster), string(board.RoleReader), string(board.RoleConnector))
	}
	values := map[string]ddbtypes.AttributeValue{
		":version": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(version)},
	}
	var roleChecks []string
	for i, role := range roles {
		key := fmt.Sprintf(":role%d", i)
		values[key] = &ddbtypes.AttributeValueMemberS{Value: role}
		roleChecks = append(roleChecks, "#role = "+key)
	}
	return ddbtypes.TransactWriteItem{ConditionCheck: &ddbtypes.ConditionCheck{
		TableName:                 aws.String(tableName),
		Key:                       key(roomPK(roomKey), memberSK(agent)),
		ConditionExpression:       aws.String("attribute_exists(PK) AND #version = :version AND (" + strings.Join(roleChecks, " OR ") + ")"),
		ExpressionAttributeNames:  map[string]string{"#version": "version", "#role": "role"},
		ExpressionAttributeValues: values,
	}}
}

func roomOpenConditionTxn(tableName string, roomKey string) ddbtypes.TransactWriteItem {
	return ddbtypes.TransactWriteItem{
		ConditionCheck: &ddbtypes.ConditionCheck{
			TableName:                 aws.String(tableName),
			Key:                       key(roomPK(roomKey), "META"),
			ConditionExpression:       aws.String("#archived = :false"),
			ExpressionAttributeNames:  map[string]string{"#archived": "archived"},
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":false": &ddbtypes.AttributeValueMemberBOOL{Value: false}},
		},
	}
}

func roomVersionConditionTxn(tableName string, roomKey string, expectedVersion int64) ddbtypes.TransactWriteItem {
	return ddbtypes.TransactWriteItem{
		ConditionCheck: &ddbtypes.ConditionCheck{
			TableName:                aws.String(tableName),
			Key:                      key(roomPK(roomKey), "META"),
			ConditionExpression:      aws.String("#archived = :false AND #version = :expectedVersion"),
			ExpressionAttributeNames: map[string]string{"#archived": "archived", "#version": "version"},
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":false":           &ddbtypes.AttributeValueMemberBOOL{Value: false},
				":expectedVersion": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprint(expectedVersion)},
			},
		},
	}
}

func auditItem(roomKey string, eventType string, actor string, target string, role board.Role, tokenJTIHash string, nowText string) ddbItem {
	return ddbItem{
		PK:            roomPK(roomKey),
		SK:            "AUDIT#audit_" + ulid.Make().String(),
		Type:          "audit",
		SchemaVersion: board.SchemaVersion,
		RoomKey:       roomKey,
		EventType:     eventType,
		Actor:         actor,
		TargetAgent:   target,
		Role:          role,
		TokenJTIHash:  tokenJTIHash,
		CreatedAt:     nowText,
	}
}

func roomFromItem(item ddbItem) board.Room {
	return board.Room{
		RoomID:      item.RoomID,
		RoomKey:     item.RoomKey,
		Name:        item.Name,
		Description: item.Description,
		Owner:       item.Owner,
		CreatedAt:   parseTime(item.CreatedAt),
		UpdatedAt:   parseTime(item.UpdatedAt),
		Version:     item.Version,
		Archived:    item.Archived,
		MemberCount: item.MemberCount,
	}
}

func membershipFromItem(item ddbItem) board.Membership {
	return board.Membership{
		RoomID:       item.RoomID,
		RoomKey:      item.RoomKey,
		Agent:        item.Agent,
		Nickname:     item.Nickname,
		NicknameKey:  item.NicknameKey,
		Role:         item.Role,
		Capabilities: append([]board.Capability(nil), item.Capabilities...),
		CreatedBy:    item.CreatedBy,
		UpdatedBy:    item.UpdatedBy,
		CreatedAt:    parseTime(item.CreatedAt),
		UpdatedAt:    parseTime(item.UpdatedAt),
		Version:      item.Version,
	}
}

func messageFromItem(item ddbItem) board.Message {
	return board.Message{
		RoomID:         item.RoomID,
		RoomKey:        item.RoomKey,
		MessageID:      item.MessageID,
		Author:         item.Author,
		AuthorNickname: item.AuthorNickname,
		Body:           item.Body,
		CreatedAt:      parseTime(item.CreatedAt),
		IdempotencyKey: item.IdempotencyKey,
		RequestHash:    item.RequestHash,
	}
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func key(pk string, sk string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{
		"PK": &ddbtypes.AttributeValueMemberS{Value: pk},
		"SK": &ddbtypes.AttributeValueMemberS{Value: sk},
	}
}

func roomPK(roomKey string) string { return "ROOM#" + roomKey }
func agentPK(agent string) string  { return "AGENT#" + agent }
func memberSK(agent string) string { return "MEMBER#" + agent }
func nicknameSK(nicknameKey string) string {
	return "NICK#" + nicknameKey
}

func memberLimitCondition(created bool) string {
	if !created {
		return ""
	}
	return " AND memberCount < :maxMembers"
}

func marshalAttribute(value any) ddbtypes.AttributeValue {
	attr, err := attributevalue.Marshal(value)
	if err != nil {
		panic(err)
	}
	return attr
}

func translateDDBWriteError(err error) error {
	var txErr *ddbtypes.TransactionCanceledException
	if errors.As(err, &txErr) {
		if transactionCanceledByConditions(txErr) {
			return board.ErrConflict
		}
		return fmt.Errorf("%w: dynamodb TransactionCanceledException", board.ErrDependency)
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "ConditionalCheckFailedException":
			return board.ErrConflict
		case "TransactionCanceledException":
			return fmt.Errorf("%w: dynamodb %s: %s", board.ErrDependency, apiErr.ErrorCode(), apiErr.ErrorMessage())
		}
		return fmt.Errorf("%w: dynamodb %s: %s", board.ErrDependency, apiErr.ErrorCode(), apiErr.ErrorMessage())
	}
	return err
}

func transactionCanceledByConditions(err *ddbtypes.TransactionCanceledException) bool {
	if len(err.CancellationReasons) == 0 {
		return false
	}
	for _, reason := range err.CancellationReasons {
		switch aws.ToString(reason.Code) {
		case "", "None", "ConditionalCheckFailed":
			continue
		default:
			return false
		}
	}
	return true
}

func translateDDBError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%w: dynamodb %s: %s", board.ErrDependency, apiErr.ErrorCode(), apiErr.ErrorMessage())
	}
	return err
}

func encodeDDBCursor(key map[string]ddbtypes.AttributeValue) string {
	if len(key) == 0 {
		return ""
	}
	values := map[string]string{}
	for name, attr := range key {
		if s, ok := attr.(*ddbtypes.AttributeValueMemberS); ok {
			values[name] = s.Value
		}
	}
	raw, _ := json.Marshal(values)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeDDBCursor(cursor string) (map[string]ddbtypes.AttributeValue, error) {
	if cursor == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return nil, err
	}
	var values map[string]string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	out := map[string]ddbtypes.AttributeValue{}
	for name, value := range values {
		out[name] = &ddbtypes.AttributeValueMemberS{Value: value}
	}
	return out, nil
}
