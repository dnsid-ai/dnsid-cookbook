package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/authorization"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/store"
)

type fakeVerifier struct{}

func (fakeVerifier) VerifyBearer(_ context.Context, token string) (board.Identity, error) {
	return board.Identity{
		Agent:        token + ".example.com",
		Issuer:       "https://api.dnsid.dev",
		Audience:     []string{"urn:test"},
		Environment:  "lab",
		TokenJTIHash: "sha256:test",
	}, nil
}

func TestHTTPAPIEndToEndBehavior(t *testing.T) {
	api := New(store.NewMemoryStore(), fakeVerifier{}, authorization.NewLocalAuthorizer())
	roomID := "security/risk brainstorm"

	create := request(t, api, http.MethodPost, "/v1/rooms", "owner", map[string]any{
		"room_id": roomID,
		"name":    "Security",
	}, nil)
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", create.Code, create.Body.String())
	}
	duplicate := request(t, api, http.MethodPost, "/v1/rooms", "owner", map[string]any{
		"room_id": roomID,
	}, nil)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d body=%s", duplicate.Code, duplicate.Body.String())
	}

	adminAgent := "admin.example.com"
	grantAdmin := request(t, api, http.MethodPut, "/v1/rooms/"+url.PathEscape(roomID)+"/allowlist/"+adminAgent, "owner", map[string]any{
		"role": "admin",
	}, nil)
	if grantAdmin.Code != http.StatusOK {
		t.Fatalf("grant admin status = %d body=%s", grantAdmin.Code, grantAdmin.Body.String())
	}

	futureAgent := "future-agent.example.com"
	grant := request(t, api, http.MethodPut, "/v1/rooms/"+url.PathEscape(roomID)+"/allowlist/"+futureAgent, "admin", map[string]any{
		"role": "poster",
	}, nil)
	if grant.Code != http.StatusOK {
		t.Fatalf("grant status = %d body=%s", grant.Code, grant.Body.String())
	}

	nickname := request(t, api, http.MethodPut, "/v1/rooms/"+url.PathEscape(roomID)+"/nickname", "future-agent", map[string]any{
		"nickname": "Wolfgang",
	}, nil)
	if nickname.Code != http.StatusOK || !strings.Contains(nickname.Body.String(), `"nickname":"Wolfgang"`) {
		t.Fatalf("nickname status/body = %d %s", nickname.Code, nickname.Body.String())
	}
	nicknameConflict := request(t, api, http.MethodPut, "/v1/rooms/"+url.PathEscape(roomID)+"/nickname", "owner", map[string]any{
		"nickname": "wolfgang",
	}, nil)
	if nicknameConflict.Code != http.StatusConflict {
		t.Fatalf("nickname conflict status = %d body=%s", nicknameConflict.Code, nicknameConflict.Body.String())
	}
	badNickname := request(t, api, http.MethodPut, "/v1/rooms/"+url.PathEscape(roomID)+"/nickname", "future-agent", map[string]any{
		"nickname": "bad nickname",
	}, nil)
	if badNickname.Code != http.StatusBadRequest {
		t.Fatalf("bad nickname status = %d body=%s", badNickname.Code, badNickname.Body.String())
	}
	unlistedNickname := request(t, api, http.MethodPut, "/v1/rooms/"+url.PathEscape(roomID)+"/nickname", "unlisted", map[string]any{
		"nickname": "unlisted",
	}, nil)
	if unlistedNickname.Code != http.StatusNotFound {
		t.Fatalf("unlisted nickname status = %d body=%s", unlistedNickname.Code, unlistedNickname.Body.String())
	}

	post := request(t, api, http.MethodPost, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "future-agent", map[string]any{
		"body": "first",
	}, map[string]string{"Idempotency-Key": "idem-1"})
	if post.Code != http.StatusCreated {
		t.Fatalf("post status = %d body=%s", post.Code, post.Body.String())
	}
	replay := request(t, api, http.MethodPost, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "future-agent", map[string]any{
		"body": "first",
	}, map[string]string{"Idempotency-Key": "idem-1"})
	if replay.Code != http.StatusOK || !strings.Contains(replay.Body.String(), `"idempotent_replay":true`) {
		t.Fatalf("replay status/body = %d %s", replay.Code, replay.Body.String())
	}
	conflict := request(t, api, http.MethodPost, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "future-agent", map[string]any{
		"body": "changed",
	}, map[string]string{"Idempotency-Key": "idem-1"})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d body=%s", conflict.Code, conflict.Body.String())
	}
	for i := 0; i < 104; i++ {
		resp := request(t, api, http.MethodPost, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "future-agent", map[string]any{
			"body": "message",
		}, map[string]string{"Idempotency-Key": fmt.Sprintf("idem-extra-%d", i)})
		if resp.Code != http.StatusCreated {
			t.Fatalf("bulk post %d status = %d body=%s", i, resp.Code, resp.Body.String())
		}
	}
	read := request(t, api, http.MethodGet, "/v1/rooms/"+url.PathEscape(roomID)+"/messages?limit=500", "future-agent", nil, nil)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"messages"`) {
		t.Fatalf("read status/body = %d %s", read.Code, read.Body.String())
	}
	var readBody struct {
		Messages []board.Message `json:"messages"`
	}
	if err := json.Unmarshal(read.Body.Bytes(), &readBody); err != nil {
		t.Fatal(err)
	}
	if len(readBody.Messages) != board.MaxLimit {
		t.Fatalf("message read should be capped at %d, got %d", board.MaxLimit, len(readBody.Messages))
	}
	if got := readBody.Messages[len(readBody.Messages)-1].AuthorNickname; got != "Wolfgang" {
		t.Fatalf("read author_nickname = %q", got)
	}
	after := request(t, api, http.MethodGet, "/v1/rooms/"+url.PathEscape(roomID)+"/messages?limit=2&after="+url.QueryEscape(readBody.Messages[0].MessageID), "future-agent", nil, nil)
	if after.Code != http.StatusOK || !strings.Contains(after.Body.String(), `"author_nickname":"Wolfgang"`) {
		t.Fatalf("after status/body = %d %s", after.Code, after.Body.String())
	}
	watch := request(t, api, http.MethodGet, "/v1/rooms/"+url.PathEscape(roomID)+"/messages?limit=2&wait=0&after="+url.QueryEscape(readBody.Messages[0].MessageID), "future-agent", nil, nil)
	if watch.Code != http.StatusOK || !strings.Contains(watch.Body.String(), `"author_nickname":"Wolfgang"`) {
		t.Fatalf("watch status/body = %d %s", watch.Code, watch.Body.String())
	}
	unlisted := request(t, api, http.MethodGet, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "unlisted", nil, nil)
	if unlisted.Code != http.StatusNotFound || !strings.Contains(unlisted.Body.String(), `"Room not found."`) {
		t.Fatalf("unlisted status/body = %d %s", unlisted.Code, unlisted.Body.String())
	}
	badIdentityBody := request(t, api, http.MethodPost, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "future-agent", map[string]any{
		"body":  "first",
		"agent": "attacker.example.com",
	}, map[string]string{"Idempotency-Key": "idem-2"})
	if badIdentityBody.Code != http.StatusBadRequest {
		t.Fatalf("identity-like body should be rejected, got %d %s", badIdentityBody.Code, badIdentityBody.Body.String())
	}
	badNicknameBody := request(t, api, http.MethodPost, "/v1/rooms/"+url.PathEscape(roomID)+"/messages", "future-agent", map[string]any{
		"body":     "first",
		"nickname": "attacker",
	}, map[string]string{"Idempotency-Key": "idem-3"})
	if badNicknameBody.Code != http.StatusBadRequest {
		t.Fatalf("nickname body should be rejected, got %d %s", badNicknameBody.Code, badNicknameBody.Body.String())
	}
}

func TestQueryWaitDefaultsCapsAndValidates(t *testing.T) {
	cases := []struct {
		name      string
		rawQuery  string
		want      int
		wantError bool
	}{
		{name: "default", want: 0},
		{name: "zero", rawQuery: "wait=0", want: 0},
		{name: "positive", rawQuery: "wait=7", want: 7},
		{name: "capped", rawQuery: "wait=999", want: board.MaxWatchSeconds},
		{name: "negative", rawQuery: "wait=-1", wantError: true},
		{name: "not integer", rawQuery: "wait=soon", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/rooms/room/messages?"+tc.rawQuery, nil)
			got, err := queryWait(req)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("wait = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestProtectedRoutesRequireBearerAuthBeforeMutation(t *testing.T) {
	api := New(store.NewMemoryStore(), fakeVerifier{}, authorization.NewLocalAuthorizer())
	req := httptest.NewRequest(http.MethodPost, "/v1/rooms", strings.NewReader(`{"room_id":"room"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	api.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	list := request(t, api, http.MethodGet, "/v1/rooms", "owner", nil, nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", list.Code, list.Body.String())
	}
	var body struct {
		Rooms []board.RoomSummary `json:"rooms"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Rooms) != 0 {
		t.Fatalf("unauthenticated create mutated rooms: %+v", body.Rooms)
	}
}

func request(t *testing.T, handler http.Handler, method string, path string, token string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+token)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}
