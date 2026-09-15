package authorization

import (
	"context"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

type Authorizer interface {
	Authorize(ctx context.Context, identity board.Identity, action board.Action, snapshot board.AuthSnapshot, authContext board.AuthContext) error
}

type LocalAuthorizer struct{}

func NewLocalAuthorizer() LocalAuthorizer {
	return LocalAuthorizer{}
}

func (a LocalAuthorizer) Authorize(_ context.Context, identity board.Identity, action board.Action, snapshot board.AuthSnapshot, authContext board.AuthContext) error {
	switch action {
	case board.ActionCreateRoom, board.ActionListOwnRooms:
		return nil
	case board.ActionUpdateAllowList:
		if authContext.NewRole == board.RoleOwner {
			return board.ErrDenied
		}
		if authContext.TargetAgent != "" && authContext.TargetAgent == snapshot.Room.Owner {
			return board.ErrDenied
		}
	}
	if snapshot.Room.Archived {
		return board.ErrDenied
	}
	if snapshot.Room.Owner == identity.Agent {
		return nil
	}
	if snapshot.Membership == nil {
		return board.ErrDenied
	}
	if !board.RoleCan(snapshot.Membership.Role, action) {
		return board.ErrDenied
	}
	return nil
}
