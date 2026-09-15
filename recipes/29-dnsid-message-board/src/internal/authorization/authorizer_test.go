package authorization

import (
	"context"
	"testing"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

func TestLocalAuthorizerPolicyMatrix(t *testing.T) {
	authorizer := NewLocalAuthorizer()
	identity := board.Identity{Agent: "agent.example.com"}
	actions := []board.Action{
		board.ActionConnectRoom,
		board.ActionReadMessages,
		board.ActionPostMessage,
		board.ActionUpdateNickname,
		board.ActionViewAllowList,
		board.ActionUpdateAllowList,
	}
	tests := map[board.Role]map[board.Action]bool{
		board.RoleOwner:     {board.ActionConnectRoom: true, board.ActionReadMessages: true, board.ActionPostMessage: true, board.ActionUpdateNickname: true, board.ActionViewAllowList: true, board.ActionUpdateAllowList: true},
		board.RoleAdmin:     {board.ActionConnectRoom: true, board.ActionReadMessages: true, board.ActionPostMessage: true, board.ActionUpdateNickname: true, board.ActionViewAllowList: true, board.ActionUpdateAllowList: true},
		board.RolePoster:    {board.ActionConnectRoom: true, board.ActionReadMessages: true, board.ActionPostMessage: true, board.ActionUpdateNickname: true, board.ActionViewAllowList: false, board.ActionUpdateAllowList: false},
		board.RoleReader:    {board.ActionConnectRoom: true, board.ActionReadMessages: true, board.ActionPostMessage: false, board.ActionUpdateNickname: true, board.ActionViewAllowList: false, board.ActionUpdateAllowList: false},
		board.RoleConnector: {board.ActionConnectRoom: true, board.ActionReadMessages: false, board.ActionPostMessage: false, board.ActionUpdateNickname: true, board.ActionViewAllowList: false, board.ActionUpdateAllowList: false},
	}
	for role, expected := range tests {
		caps, _ := board.CapabilitiesForRole(role)
		snapshot := board.AuthSnapshot{
			Room: board.Room{Owner: "owner.example.com"},
			Membership: &board.Membership{
				Agent:        identity.Agent,
				Role:         role,
				Capabilities: caps,
			},
		}
		if role == board.RoleOwner {
			snapshot.Room.Owner = identity.Agent
		}
		for _, action := range actions {
			err := authorizer.Authorize(context.Background(), identity, action, snapshot, board.AuthContext{})
			if expected[action] && err != nil {
				t.Fatalf("%s %s should allow: %v", role, action, err)
			}
			if !expected[action] && err == nil {
				t.Fatalf("%s %s should deny", role, action)
			}
		}
	}
}

func TestLocalAuthorizerOwnerProtection(t *testing.T) {
	authorizer := NewLocalAuthorizer()
	identity := board.Identity{Agent: "owner.example.com"}
	snapshot := board.AuthSnapshot{Room: board.Room{Owner: identity.Agent}}
	for _, ctx := range []board.AuthContext{
		{Operation: "grant", TargetAgent: identity.Agent, NewRole: board.RoleAdmin},
		{Operation: "grant", TargetAgent: "other.example.com", NewRole: board.RoleOwner},
	} {
		if err := authorizer.Authorize(context.Background(), identity, board.ActionUpdateAllowList, snapshot, ctx); err == nil {
			t.Fatalf("expected owner-protection deny for %+v", ctx)
		}
	}
}
