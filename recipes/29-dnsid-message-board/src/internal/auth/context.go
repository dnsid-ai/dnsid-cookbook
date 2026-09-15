package auth

import (
	"context"
	"errors"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

type contextKey string

const identityKey contextKey = "dnsid_identity"

func WithIdentity(ctx context.Context, identity board.Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

func IdentityFromContext(ctx context.Context) (board.Identity, bool) {
	identity, ok := ctx.Value(identityKey).(board.Identity)
	return identity, ok
}

func RequireIdentity(ctx context.Context) (board.Identity, error) {
	identity, ok := IdentityFromContext(ctx)
	if !ok {
		return board.Identity{}, errors.New("missing authenticated identity")
	}
	return identity, nil
}
