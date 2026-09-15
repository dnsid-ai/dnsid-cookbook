package authorization

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	avptypes "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"

	"github.com/identity-digital/dnsid-cookbook/recipes/29-dnsid-message-board/src/internal/board"
)

type AVPClient interface {
	IsAuthorized(ctx context.Context, input *verifiedpermissions.IsAuthorizedInput, optFns ...func(*verifiedpermissions.Options)) (*verifiedpermissions.IsAuthorizedOutput, error)
}

type AVPAuthorizer struct {
	client        AVPClient
	policyStoreID string
}

func NewAVPAuthorizer(client AVPClient, policyStoreID string) AVPAuthorizer {
	return AVPAuthorizer{client: client, policyStoreID: policyStoreID}
}

func (a AVPAuthorizer) Authorize(ctx context.Context, identity board.Identity, action board.Action, snapshot board.AuthSnapshot, authContext board.AuthContext) error {
	input := &verifiedpermissions.IsAuthorizedInput{
		PolicyStoreId: aws.String(a.policyStoreID),
		Principal:     entityID("DNSidBoard::Agent", identity.Agent),
		Action:        &avptypes.ActionIdentifier{ActionType: aws.String("DNSidBoard::Action"), ActionId: aws.String(string(action))},
		Resource:      resourceID(action, snapshot),
		Entities:      entities(identity, snapshot, authContext),
		Context:       contextMap(authContext),
	}
	out, err := a.client.IsAuthorized(ctx, input)
	if err != nil {
		return fmt.Errorf("%w: avp is-authorized: %v", board.ErrDependency, err)
	}
	if len(out.Errors) > 0 {
		return fmt.Errorf("%w: avp evaluation errors: %v", board.ErrDependency, out.Errors)
	}
	if out.Decision != avptypes.DecisionAllow {
		return board.ErrDenied
	}
	return nil
}

func resourceID(action board.Action, snapshot board.AuthSnapshot) *avptypes.EntityIdentifier {
	switch action {
	case board.ActionCreateRoom, board.ActionListOwnRooms:
		return entityID("DNSidBoard::Service", "message-board")
	default:
		return entityID("DNSidBoard::Room", snapshot.Room.RoomKey)
	}
}

func entities(identity board.Identity, snapshot board.AuthSnapshot, authContext board.AuthContext) avptypes.EntitiesDefinition {
	items := []avptypes.EntityItem{
		{
			Identifier: entityID("DNSidBoard::Agent", identity.Agent),
			Attributes: map[string]avptypes.AttributeValue{
				"fqdn":        stringAttr(identity.Agent),
				"issuer":      stringAttr(identity.Issuer),
				"environment": stringAttr(identity.Environment),
			},
		},
		{
			Identifier: entityID("DNSidBoard::Service", "message-board"),
		},
	}
	if snapshot.Room.RoomKey == "" {
		return &avptypes.EntitiesDefinitionMemberEntityList{Value: items}
	}
	roomKey := snapshot.Room.RoomKey
	items = append(items, avptypes.EntityItem{
		Identifier: entityID("DNSidBoard::Room", roomKey),
		Attributes: map[string]avptypes.AttributeValue{
			"roomId":        stringAttr(snapshot.Room.RoomID),
			"owner":         entityAttr("DNSidBoard::Agent", snapshot.Room.Owner),
			"ownerRole":     entityAttr("DNSidBoard::RoomRole", roomKey+"#owner"),
			"adminRole":     entityAttr("DNSidBoard::RoomRole", roomKey+"#admin"),
			"posterRole":    entityAttr("DNSidBoard::RoomRole", roomKey+"#poster"),
			"readerRole":    entityAttr("DNSidBoard::RoomRole", roomKey+"#reader"),
			"connectorRole": entityAttr("DNSidBoard::RoomRole", roomKey+"#connector"),
			"archived":      boolAttr(snapshot.Room.Archived),
		},
	})
	for _, role := range []board.Role{board.RoleOwner, board.RoleAdmin, board.RolePoster, board.RoleReader, board.RoleConnector} {
		items = append(items, avptypes.EntityItem{Identifier: entityID("DNSidBoard::RoomRole", roomKey+"#"+string(role))})
	}
	if snapshot.Membership != nil {
		items[0].Parents = []avptypes.EntityIdentifier{*entityID("DNSidBoard::RoomRole", roomKey+"#"+string(snapshot.Membership.Role))}
	}
	if snapshot.Room.Owner != "" && snapshot.Room.Owner != identity.Agent {
		items = append(items, avptypes.EntityItem{
			Identifier: entityID("DNSidBoard::Agent", snapshot.Room.Owner),
			Attributes: map[string]avptypes.AttributeValue{
				"fqdn":        stringAttr(snapshot.Room.Owner),
				"issuer":      stringAttr(identity.Issuer),
				"environment": stringAttr(identity.Environment),
			},
			Parents: []avptypes.EntityIdentifier{*entityID("DNSidBoard::RoomRole", roomKey+"#owner")},
		})
	}
	if authContext.TargetAgent != "" && authContext.TargetAgent != identity.Agent && authContext.TargetAgent != snapshot.Room.Owner {
		items = append(items, avptypes.EntityItem{
			Identifier: entityID("DNSidBoard::Agent", authContext.TargetAgent),
			Attributes: map[string]avptypes.AttributeValue{
				"fqdn":        stringAttr(authContext.TargetAgent),
				"issuer":      stringAttr(identity.Issuer),
				"environment": stringAttr(identity.Environment),
			},
		})
	}
	return &avptypes.EntitiesDefinitionMemberEntityList{Value: items}
}

func contextMap(authContext board.AuthContext) avptypes.ContextDefinition {
	if authContext.Operation == "" && authContext.TargetAgent == "" && authContext.NewRole == "" {
		return nil
	}
	values := map[string]avptypes.AttributeValue{}
	if authContext.Operation != "" {
		values["operation"] = stringAttr(authContext.Operation)
	}
	if authContext.TargetAgent != "" {
		values["targetAgent"] = entityAttr("DNSidBoard::Agent", authContext.TargetAgent)
	}
	if authContext.NewRole != "" {
		values["newRole"] = stringAttr(string(authContext.NewRole))
	}
	return &avptypes.ContextDefinitionMemberContextMap{Value: values}
}

func entityID(entityType string, entityID string) *avptypes.EntityIdentifier {
	return &avptypes.EntityIdentifier{EntityType: aws.String(entityType), EntityId: aws.String(entityID)}
}

func stringAttr(value string) avptypes.AttributeValue {
	return &avptypes.AttributeValueMemberString{Value: value}
}

func boolAttr(value bool) avptypes.AttributeValue {
	return &avptypes.AttributeValueMemberBoolean{Value: value}
}

func entityAttr(entityType string, id string) avptypes.AttributeValue {
	return &avptypes.AttributeValueMemberEntityIdentifier{Value: *entityID(entityType, id)}
}
