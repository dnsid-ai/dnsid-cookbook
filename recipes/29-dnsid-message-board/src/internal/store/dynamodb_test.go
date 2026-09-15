package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

func TestDynamoDBStoreSetNicknameSendsReservationTransaction(t *testing.T) {
	actor := board.Identity{Agent: "agent.example.com"}
	server, transactions := newDynamoDBTestServer(t, []map[string]any{
		ddbMembershipItem("room", "room", actor.Agent, board.RolePoster, "old", "old", 3),
	})
	defer server.Close()
	store := NewDynamoDBStore(newDynamoDBTestClient(server.URL), "table")
	store.now = func() time.Time { return time.Date(2026, 6, 5, 1, 2, 3, 0, time.UTC) }

	member, err := store.SetNickname(context.Background(), actor, SetNicknameInput{
		RoomID:             "room",
		Nickname:           "Wolfgang",
		ActorMemberVersion: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if member.Nickname != "Wolfgang" || member.NicknameKey != "wolfgang" || member.Version != 4 {
		t.Fatalf("updated member = %+v", member)
	}
	if len(*transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(*transactions))
	}
	assertTransactionContains(t, (*transactions)[0], []string{
		`"ConditionExpression":"#archived = :false"`,
		`"ConditionExpression":"attribute_exists(PK) AND #version = :version AND #role = :role"`,
		`"S":"NICK#old"`,
		`"S":"NICK#wolfgang"`,
		`"ConditionExpression":"attribute_not_exists(PK) OR #agent = :agent"`,
	})
}

func TestDynamoDBStoreRevokeAllowlistReleasesNicknameReservation(t *testing.T) {
	owner := board.Identity{Agent: "owner.example.com"}
	target := "agent.example.com"
	server, transactions := newDynamoDBTestServer(t, []map[string]any{
		ddbRoomItem("room", "room", owner.Agent, 8),
		ddbMembershipItem("room", "room", target, board.RolePoster, "Wolfgang", "wolfgang", 5),
	})
	defer server.Close()
	store := NewDynamoDBStore(newDynamoDBTestClient(server.URL), "table")
	store.now = func() time.Time { return time.Date(2026, 6, 5, 1, 2, 3, 0, time.UTC) }

	removed, err := store.RevokeAllowlist(context.Background(), owner, RevokeInput{
		RoomID:              "room",
		TargetAgent:         target,
		ActorMemberVersion:  4,
		ExpectedRoomVersion: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("removed = false")
	}
	if len(*transactions) != 1 {
		t.Fatalf("transactions = %d, want 1", len(*transactions))
	}
	assertTransactionContains(t, (*transactions)[0], []string{
		`#version = :targetVersion`,
		`#nicknameKey = :nicknameKey`,
		`"S":"NICK#wolfgang"`,
		`"ConditionExpression":"#agent = :agent"`,
	})
}

func TestDynamoDBStoreClassifiesPostConditionConflicts(t *testing.T) {
	ctx := context.Background()
	actor := board.Identity{Agent: "agent.example.com"}
	archivedRoom := ddbRoomItem("room", "room", "owner.example.com", 8)
	archivedRoom["archived"] = ddbBool(true)

	tests := []struct {
		name               string
		getItems           []map[string]any
		actorMemberVersion int64
		wantErr            error
	}{
		{
			name:     "missing room is concealed as denied",
			getItems: []map[string]any{{}},
			wantErr:  board.ErrDenied,
		},
		{
			name:     "archived room is concealed as denied",
			getItems: []map[string]any{archivedRoom},
			wantErr:  board.ErrDenied,
		},
		{
			name:     "missing actor membership is concealed as denied",
			getItems: []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), {}},
			wantErr:  board.ErrDenied,
		},
		{
			name:               "stale actor membership version remains a conflict",
			getItems:           []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), ddbMembershipItem("room", "room", actor.Agent, board.RolePoster, "", "", 5)},
			actorMemberVersion: 4,
			wantErr:            board.ErrConflict,
		},
		{
			name:               "actor without post permission is concealed as denied",
			getItems:           []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), ddbMembershipItem("room", "room", actor.Agent, board.RoleReader, "", "", 5)},
			actorMemberVersion: 5,
			wantErr:            board.ErrDenied,
		},
		{
			name:               "authorized actor leaves the transaction failure as a conflict",
			getItems:           []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), ddbMembershipItem("room", "room", actor.Agent, board.RolePoster, "", "", 5)},
			actorMemberVersion: 5,
			wantErr:            board.ErrConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, _ := newDynamoDBTestServer(t, tt.getItems)
			defer server.Close()
			store := NewDynamoDBStore(newDynamoDBTestClient(server.URL), "table")

			err := store.classifyPostConditionConflict(ctx, actor, "room", tt.actorMemberVersion)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestDynamoDBStoreReplayPostClassifiesAuthorizationConflict(t *testing.T) {
	ctx := context.Background()
	actor := board.Identity{Agent: "agent.example.com"}
	idem := ddbItem{MessageID: "msg_1", RequestHash: "hash-1"}

	tests := []struct {
		name               string
		getItems           []map[string]any
		actorMemberVersion int64
		wantErr            error
	}{
		{
			name:               "revoked actor is concealed as denied",
			getItems:           []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), {}},
			actorMemberVersion: 5,
			wantErr:            board.ErrDenied,
		},
		{
			name:               "reader actor is concealed as denied",
			getItems:           []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), ddbMembershipItem("room", "room", actor.Agent, board.RoleReader, "", "", 5)},
			actorMemberVersion: 5,
			wantErr:            board.ErrDenied,
		},
		{
			name:               "stale actor version remains conflict",
			getItems:           []map[string]any{ddbRoomItem("room", "room", "owner.example.com", 8), ddbMembershipItem("room", "room", actor.Agent, board.RolePoster, "", "", 5)},
			actorMemberVersion: 4,
			wantErr:            board.ErrConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, _ := newDynamoDBTestServerWithFailingTransactions(t, tt.getItems)
			defer server.Close()
			store := NewDynamoDBStore(newDynamoDBTestClient(server.URL), "table")

			_, err := store.replayPost(ctx, actor, PostInput{
				RoomID:             "room",
				IdempotencyKey:     "idem-1",
				RequestHash:        "hash-1",
				ActorMemberVersion: tt.actorMemberVersion,
			}, "room", idem)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func newDynamoDBTestClient(endpoint string) *dynamodb.Client {
	return dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider("test-key", "test-secret", ""),
		BaseEndpoint: aws.String(endpoint),
	})
}

func newDynamoDBTestServer(t *testing.T, getItems []map[string]any) (*httptest.Server, *[]map[string]any) {
	return newDynamoDBTestServerWithTransactHandler(t, getItems, func(w http.ResponseWriter, _ map[string]any) {
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})
}

func newDynamoDBTestServerWithFailingTransactions(t *testing.T, getItems []map[string]any) (*httptest.Server, *[]map[string]any) {
	return newDynamoDBTestServerWithTransactHandler(t, getItems, func(w http.ResponseWriter, _ map[string]any) {
		w.Header().Set("X-Amzn-Errortype", "TransactionCanceledException")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"__type":  "com.amazonaws.dynamodb.v20120810#TransactionCanceledException",
			"message": "transaction cancelled",
			"CancellationReasons": []map[string]any{
				{"Code": "ConditionalCheckFailed"},
				{"Code": "ConditionalCheckFailed"},
			},
		})
	})
}

func newDynamoDBTestServerWithTransactHandler(t *testing.T, getItems []map[string]any, handleTransact func(http.ResponseWriter, map[string]any)) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	nextGet := 0
	transactions := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		switch r.Header.Get("X-Amz-Target") {
		case "DynamoDB_20120810.GetItem":
			if nextGet >= len(getItems) {
				t.Errorf("unexpected GetItem request: %s", string(raw))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Item": getItems[nextGet]})
			nextGet++
		case "DynamoDB_20120810.TransactWriteItems":
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("decode transaction request: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			transactions = append(transactions, body)
			handleTransact(w, body)
		default:
			t.Errorf("unexpected DynamoDB target %q body=%s", r.Header.Get("X-Amz-Target"), string(raw))
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	return server, &transactions
}

func ddbRoomItem(roomID string, roomKey string, owner string, version int64) map[string]any {
	return map[string]any{
		"PK":            ddbS(roomPK(roomKey)),
		"SK":            ddbS("META"),
		"type":          ddbS("room"),
		"schemaVersion": ddbN(board.SchemaVersion),
		"roomId":        ddbS(roomID),
		"roomKey":       ddbS(roomKey),
		"name":          ddbS(roomID),
		"owner":         ddbS(owner),
		"version":       ddbN(version),
		"archived":      ddbBool(false),
		"memberCount":   ddbN(2),
	}
}

func ddbMembershipItem(roomID string, roomKey string, agent string, role board.Role, nickname string, nicknameKey string, version int64) map[string]any {
	item := map[string]any{
		"PK":            ddbS(roomPK(roomKey)),
		"SK":            ddbS(memberSK(agent)),
		"type":          ddbS("membership"),
		"schemaVersion": ddbN(board.SchemaVersion),
		"roomId":        ddbS(roomID),
		"roomKey":       ddbS(roomKey),
		"agent":         ddbS(agent),
		"role":          ddbS(string(role)),
		"version":       ddbN(version),
		"archived":      ddbBool(false),
	}
	if nickname != "" {
		item["nickname"] = ddbS(nickname)
		item["nicknameKey"] = ddbS(nicknameKey)
	}
	return item
}

func ddbS(value string) map[string]any {
	return map[string]any{"S": value}
}

func ddbN(value any) map[string]any {
	return map[string]any{"N": fmt.Sprint(value)}
}

func ddbBool(value bool) map[string]any {
	return map[string]any{"BOOL": value}
}

func assertTransactionContains(t *testing.T, body map[string]any, needles []string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, needle := range needles {
		if !strings.Contains(text, needle) {
			t.Fatalf("transaction does not contain %s\n%s", needle, text)
		}
	}
}
