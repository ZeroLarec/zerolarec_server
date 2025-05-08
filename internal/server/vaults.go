package server

import (
	"context"
	"log"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func toProtoVault(vault *storage.Vault) *apiv1.Vault {
	return &apiv1.Vault{
		VaultId:     vault.VaultID,
		Name:        vault.Name,
		Description: vault.Description,
		CreatedAt:   timestamppb.New(vault.CreatedAt),
		UpdatedAt:   timestamppb.New(vault.UpdatedAt),
	}
}
func (s *Server) ListVaults(ctx context.Context, req *apiv1.ListVaultsRequest) (*apiv1.ListVaultsResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("ListVaults: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	vaults, err := s.store.ListVaults(ctx, callerID, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoVaults := make([]*apiv1.Vault, len(vaults))
	for i, vault := range vaults {
		protoVaults[i] = toProtoVault(vault)
	}

	return &apiv1.ListVaultsResponse{Vaults: protoVaults}, nil
}

func (s *Server) GetVault(ctx context.Context, req *apiv1.GetVaultRequest) (*apiv1.Vault, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("GetVault: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	vault, err := s.store.GetVault(ctx, callerID, req.VaultId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoVault(vault), nil
}

func (s *Server) CreateVault(ctx context.Context, req *apiv1.CreateVaultRequest) (*apiv1.Vault, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("CreateVault: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	vault, err := s.store.CreateVault(ctx, callerID, req.Name, req.Description, req.VaultKeyProtected)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoVault(vault), nil
}

func (s *Server) UpdateVault(ctx context.Context, req *apiv1.UpdateVaultRequest) (*apiv1.Vault, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("UpdateVault: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	vault, err := s.store.UpdateVault(ctx, callerID, req.VaultId, req.Name, req.Description)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoVault(vault), nil
}

func (s *Server) DeleteVault(ctx context.Context, req *apiv1.DeleteVaultRequest) (*apiv1.DeleteVaultResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("DeleteVault: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	err := s.store.DeleteVault(ctx, callerID, req.VaultId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.DeleteVaultResponse{}, nil
}

func (s *Server) ListVaultMembers(ctx context.Context, req *apiv1.ListVaultMembersRequest) (*apiv1.ListVaultMembersResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("ListVaultMembers: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	vaultMembers, err := s.store.ListVaultMembers(ctx, callerID, req.VaultId, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoVaultMembers := make([]*apiv1.User, len(vaultMembers))
	for i, vaultMember := range vaultMembers {
		protoVaultMembers[i] = toProtoUser(vaultMember)
	}

	return &apiv1.ListVaultMembersResponse{Users: protoVaultMembers}, nil
}

func (s *Server) AddMember(ctx context.Context, req *apiv1.AddMemberRequest) (*apiv1.AddMemberResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("AddMember: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	err := s.store.AddVaultMember(ctx, callerID, req.VaultId, req.UserId, req.VaultKeyProtected)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.AddMemberResponse{}, nil
}

func (s *Server) RemoveMember(ctx context.Context, req *apiv1.RemoveMemberRequest) (*apiv1.RemoveMemberResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("RemoveMember: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	err := s.store.RemoveVaultMember(ctx, callerID, req.VaultId, req.UserId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.RemoveMemberResponse{}, nil
}

func (s *Server) GetVaultKeyProtected(ctx context.Context, req *apiv1.GetVaultKeyProtectedRequest) (*apiv1.GetVaultKeyProtectedResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("GetVaultKeyProtected: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	vaultKeyProtected, err := s.store.GetVaultKeyProtected(ctx, callerID, req.VaultId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.GetVaultKeyProtectedResponse{VaultKeyProtected: vaultKeyProtected}, nil
}
