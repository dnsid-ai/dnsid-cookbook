package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	avptypes "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

type fakeAVPClient struct {
	decision avptypes.Decision
	input    *verifiedpermissions.IsAuthorizedInput
}

func (f *fakeAVPClient) IsAuthorized(_ context.Context, input *verifiedpermissions.IsAuthorizedInput, _ ...func(*verifiedpermissions.Options)) (*verifiedpermissions.IsAuthorizedOutput, error) {
	f.input = input
	return &verifiedpermissions.IsAuthorizedOutput{Decision: f.decision}, nil
}

func TestAVPAuthorizerBuildsStructuredRequestAndMapsDeny(t *testing.T) {
	client := &fakeAVPClient{decision: avptypes.DecisionAllow}
	authorizer := NewAVPAuthorizer(client, "store-id")
	identity := board.Identity{Agent: "owner.example.com", Issuer: "https://api.dev.dnsid.ai", Environment: "lab"}
	snapshot := board.AuthSnapshot{
		Room: board.Room{
			RoomID:    "room",
			RoomKey:   "cm9vbQ",
			Owner:     identity.Agent,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Membership: &board.Membership{Agent: identity.Agent, Role: board.RoleOwner},
	}
	if err := authorizer.Authorize(context.Background(), identity, board.ActionConnectRoom, snapshot, board.AuthContext{}); err != nil {
		t.Fatal(err)
	}
	if client.input == nil || client.input.Entities == nil || client.input.Principal == nil || client.input.Resource == nil {
		t.Fatalf("expected structured AVP request, got %+v", client.input)
	}

	client.decision = avptypes.DecisionDeny
	if err := authorizer.Authorize(context.Background(), identity, board.ActionConnectRoom, snapshot, board.AuthContext{}); !errors.Is(err, board.ErrDenied) {
		t.Fatalf("expected board.ErrDenied, got %v", err)
	}
}
