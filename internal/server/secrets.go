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

func toProtoSecret(secret *storage.Secret) *apiv1.Secret {
	return &apiv1.Secret{
		SecretId:    secret.SecretID,
		Name:        secret.Name,
		Description: secret.Description,
		KeyValues: &apiv1.KeyValues{
			KeyValues: secret.KeyValues,
		},
		CreatedAt: timestamppb.New(secret.CreatedAt),
		UpdatedAt: timestamppb.New(secret.UpdatedAt),
	}
}

func (s *Server) ListSecrets(ctx context.Context, req *apiv1.ListSecretsRequest) (*apiv1.ListSecretsResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("ListSecrets: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	secrets, err := s.store.ListSecrets(ctx, callerID, req.VaultId, int(req.Offset), int(req.Limit))
	if err != nil {
		return nil, processStorageErr(err)
	}

	protoSecrets := make([]*apiv1.Secret, len(secrets))
	for i, secret := range secrets {
		protoSecrets[i] = toProtoSecret(secret)
	}

	return &apiv1.ListSecretsResponse{Secrets: protoSecrets}, nil
}

func (s *Server) GetSecret(ctx context.Context, req *apiv1.GetSecretRequest) (*apiv1.Secret, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("GetSecret: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	secret, err := s.store.GetSecret(ctx, callerID, req.VaultId, req.SecretId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoSecret(secret), nil
}

func (s *Server) CreateSecret(ctx context.Context, req *apiv1.CreateSecretRequest) (*apiv1.Secret, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		log.Println("CreateSecret: failed to get user ID from context")
		return nil, status.Error(codes.Internal, "internal error")
	}

	secret, err := s.store.CreateSecret(ctx, callerID, req.VaultId, req.Name, req.Description, req.KeyValues.KeyValues)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoSecret(secret), nil
}
