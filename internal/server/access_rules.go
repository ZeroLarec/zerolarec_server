package server

import (
	"context"
	"log"
	"time"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func toProtoPermission(permission storage.Permission) (apiv1.Permission, error) {
	var permPb apiv1.Permission

	switch permission {
	case storage.PermissionSecretCreate:
		permPb = apiv1.Permission_SECRET_CREATE
	case storage.PermissionSecretGet:
		permPb = apiv1.Permission_SECRET_GET
	case storage.PermissionSecretUpdate:
		permPb = apiv1.Permission_SECRET_UPDATE
	case storage.PermissionSecretDelete:
		permPb = apiv1.Permission_SECRET_DELETE
	case storage.PermissionSecretGrantAccess:
		permPb = apiv1.Permission_SECRET_GRANT_ACCESS

	case storage.PermissionVaultUpdate:
		permPb = apiv1.Permission_VAULT_UPDATE
	case storage.PermissionVaultDelete:
		permPb = apiv1.Permission_VAULT_DELETE
	case storage.PermissionVaultManageMembers:
		permPb = apiv1.Permission_VAULT_MANAGE_MEMBERS
	case storage.PermissionVaultGrantAccess:
		permPb = apiv1.Permission_VAULT_GRANT_ACCESS
	default:
		return apiv1.Permission_PERMISSION_UNDEFINED, status.Errorf(codes.InvalidArgument, "invalid permission: %s", permission)
	}

	return permPb, nil
}

func toStoragePermission(permPb apiv1.Permission) (storage.Permission, error) {
	var perm storage.Permission

	switch permPb {
	case apiv1.Permission_SECRET_CREATE:
		perm = storage.PermissionSecretCreate
	case apiv1.Permission_SECRET_GET:
		perm = storage.PermissionSecretGet
	case apiv1.Permission_SECRET_UPDATE:
		perm = storage.PermissionSecretUpdate
	case apiv1.Permission_SECRET_DELETE:
		perm = storage.PermissionSecretDelete
	case apiv1.Permission_SECRET_GRANT_ACCESS:
		perm = storage.PermissionSecretGrantAccess

	case apiv1.Permission_VAULT_UPDATE:
		perm = storage.PermissionVaultUpdate
	case apiv1.Permission_VAULT_DELETE:
		perm = storage.PermissionVaultDelete
	case apiv1.Permission_VAULT_MANAGE_MEMBERS:
		perm = storage.PermissionVaultManageMembers
	case apiv1.Permission_VAULT_GRANT_ACCESS:
		perm = storage.PermissionVaultGrantAccess
	default:
		return "", status.Errorf(codes.InvalidArgument, "invalid permission: %s", permPb)
	}

	return perm, nil
}

func toProtoAccessRule(accessRule *storage.AccessRule) (*apiv1.AccessRule, error) {
	protoAccessRule := &apiv1.AccessRule{
		AccessRuleId: accessRule.AccessRuleID,
		UserId:       accessRule.UserID,
		VaultId:      accessRule.VaultID,
		SecretId:     accessRule.SecretID,
		Description:  accessRule.Description,
		Permissions:  make([]apiv1.Permission, 0, len(accessRule.Permissions)),
		ExpiresAt:    timestamppb.New(accessRule.ExpiresAt),
		CreatedAt:    timestamppb.New(accessRule.CreatedAt),
		UpdatedAt:    timestamppb.New(accessRule.UpdatedAt),
	}

	for _, permission := range accessRule.Permissions {
		permPb, err := toProtoPermission(permission)
		if err != nil {
			return nil, err
		}
		protoAccessRule.Permissions = append(protoAccessRule.Permissions, permPb)
	}

	return protoAccessRule, nil
}

func (s *Server) ListAccessRules(ctx context.Context, req *apiv1.ListAccessRulesRequest) (*apiv1.ListAccessRulesResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("ListAccessRules: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	accessRules, err := s.store.ListAccessRules(ctx, callerID, req.VaultId, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoAccessRules := make([]*apiv1.AccessRule, len(accessRules))
	for i, accessRule := range accessRules {
		protoAccessRule, err := toProtoAccessRule(accessRule)
		if err != nil {
			return nil, err
		}
		protoAccessRules[i] = protoAccessRule
	}

	return &apiv1.ListAccessRulesResponse{AccessRules: protoAccessRules}, nil
}

func (s *Server) GetAccessRule(ctx context.Context, req *apiv1.GetAccessRuleRequest) (*apiv1.AccessRule, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("GetAccessRule: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	accessRule, err := s.store.GetAccessRule(ctx, callerID, req.AccessRuleId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoAccessRule, err := toProtoAccessRule(accessRule)
	if err != nil {
		return nil, err
	}

	return protoAccessRule, nil
}

func (s *Server) CreateAccessRule(ctx context.Context, req *apiv1.CreateAccessRuleRequest) (*apiv1.AccessRule, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("CreateAccessRule: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	permissions := make([]storage.Permission, 0, len(req.Permissions))
	for _, permPb := range req.Permissions {
		perm, err := toStoragePermission(permPb)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}
	accessRule, err := s.store.CreateAccessRule(ctx, callerID, req.UserId, req.VaultId, req.SecretId, req.Description, permissions, req.ExpiresAt.AsTime())
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoAccessRule, err := toProtoAccessRule(accessRule)
	if err != nil {
		return nil, err
	}

	return protoAccessRule, nil
}

func (s *Server) UpdateAccessRule(ctx context.Context, req *apiv1.UpdateAccessRuleRequest) (*apiv1.AccessRule, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("UpdateAccessRule: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	var perms []storage.Permission
	if req.Permissions != nil {
		perms = make([]storage.Permission, 0, len(req.Permissions.Permissions))
		for _, permPb := range req.Permissions.Permissions {
			perm, err := toStoragePermission(permPb)
			if err != nil {
				return nil, err
			}
			perms = append(perms, perm)
		}
	}
	var expiresAt time.Time
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt.AsTime()
	}

	accessRule, err := s.store.UpdateAccessRule(ctx, callerID, req.AccessRuleId, req.Description, &perms, &expiresAt)
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoAccessRule, err := toProtoAccessRule(accessRule)
	if err != nil {
		return nil, err
	}

	return protoAccessRule, nil
}

func (s *Server) DeleteAccessRule(ctx context.Context, req *apiv1.DeleteAccessRuleRequest) (*apiv1.DeleteAccessRuleResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("DeleteAccessRule: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	err := s.store.DeleteAccessRule(ctx, callerID, req.AccessRuleId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.DeleteAccessRuleResponse{}, nil
}
