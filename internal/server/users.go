package server

import (
	"context"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func toProtoUser(user *storage.User) *apiv1.User {
	return &apiv1.User{
		UserId:    user.UserID,
		Login:     user.Login,
		PublicKey: user.PublicKey,
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
	}
}

func (s *Server) GetUser(ctx context.Context, req *apiv1.GetUserRequest) (*apiv1.User, error) {
	user, err := s.store.GetUser(ctx, req.UserId)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoUser(user), nil
}

func (s *Server) GetUserPrivateKeyProtected(ctx context.Context, req *apiv1.GetUserPrivateKeyProtectedRequest) (*apiv1.GetUserPrivateKeyProtectedResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		return nil, status.Error(codes.Internal, "internal error")
	}

	privateKeyProtected, err := s.store.GetUserPrivateKeyProtected(ctx, callerID)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.GetUserPrivateKeyProtectedResponse{
		PrivateKeyProtected: privateKeyProtected,
	}, nil
}

func (s *Server) UpdateUser(ctx context.Context, req *apiv1.UpdateUserRequest) (*apiv1.User, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		return nil, status.Error(codes.Internal, "internal error")
	}

	user, err := s.store.UpdateUser(ctx, callerID, req.Login)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return toProtoUser(user), nil
}

func (s *Server) DeleteUser(ctx context.Context, req *apiv1.DeleteUserRequest) (*apiv1.DeleteUserResponse, error) {
	callerID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		return nil, status.Error(codes.Internal, "internal error")
	}

	err := s.store.DeleteUser(ctx, callerID)
	if err != nil {
		return nil, processStorageErr(err)
	}

	return &apiv1.DeleteUserResponse{}, nil
}
