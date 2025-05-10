package server

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const userIDContextKey = "user_id"

func (s *Server) Register(ctx context.Context, req *apiv1.RegisterRequest) (*apiv1.RegisterResponse, error) {
	if len(req.Password) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Password is required")
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("failed to generate password hash: %s", err.Error())
		return nil, status.Error(codes.Internal, "internal error")
	}

	user, err := s.store.CreateUser(ctx, req.Login, req.PublicKey, passwordHash)
	if err != nil {
		return nil, processStorageErr(err)
	}

	accessToken, err := generateAccessToken(user.UserID, []byte(s.cfg.Secret))
	if err != nil {
		log.Printf("failed to generate access token: %s", err.Error())
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &apiv1.RegisterResponse{
		User: &apiv1.User{
			UserId:    user.UserID,
			Login:     user.Login,
			PublicKey: user.PublicKey,
		},
		AccessToken: accessToken,
	}, nil
}

func generateAccessToken(userID string, secret []byte) (string, error) {
	return jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	).SignedString(secret)
}

func (s *Server) Login(ctx context.Context, req *apiv1.LoginRequest) (*apiv1.LoginResponse, error) {
	actualPasswordHash, err := s.store.GetUserPasswordHashByLogin(ctx, req.Login)
	if err != nil {
		return nil, processStorageErr(err)
	}

	if err := bcrypt.CompareHashAndPassword(actualPasswordHash, []byte(req.Password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, status.Error(codes.Unauthenticated, "invalid login or password")
		}
	}

	user, err := s.store.GetUserByLogin(ctx, req.Login)
	if err != nil {
		return nil, processStorageErr(err)
	}

	accessToken, err := generateAccessToken(user.UserID, []byte(s.cfg.Secret))
	if err != nil {
		log.Printf("failed to generate access token: %s", err.Error())
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &apiv1.LoginResponse{
		AccessToken: accessToken,
		User: &apiv1.User{
			UserId:    user.UserID,
			Login:     user.Login,
			PublicKey: user.PublicKey,
		},
	}, nil
}

var unAuthAllowMethods = map[string]struct{}{
	apiv1.HealthService_Check_FullMethodName:          {},
	apiv1.AuthenticateService_Login_FullMethodName:    {},
	apiv1.AuthenticateService_Register_FullMethodName: {},
}

func NewAuthInterceptor(secret []byte) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if _, ok := unAuthAllowMethods[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "failed to parse metadata from incoming context")
		}

		token, err := extractToken(md)
		if err != nil {
			return nil, err
		}

		userID, err := authenticate(token, secret)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, userIDContextKey, userID)

		return handler(ctx, req)
	}
}

func authenticate(accessToken string, secret []byte) (userID string, err error) {
	if len(accessToken) == 0 {
		return "", status.Error(codes.Unauthenticated, "access token not found")
	}

	token, err := jwt.ParseWithClaims(accessToken, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "invalid or expired access token")
	}
	if !token.Valid {
		return "", status.Error(codes.Unauthenticated, "invalid or expired access token")
	}

	userID, err = token.Claims.GetSubject()
	if err != nil {
		log.Println("unexpected error while authenticate get subject: %s", err.Error())
		return "", status.Error(codes.Internal, "internal error")
	}

	return userID, nil
}

func extractToken(md metadata.MD) (string, error) {
	authHeaders := md.Get("Authorization")
	if len(authHeaders) != 1 {
		return "", status.Error(codes.Unauthenticated, "Authorization header is required")
	}

	token := strings.TrimPrefix(authHeaders[0], "Bearer ")
	if token == "" {
		return "", status.Error(codes.Unauthenticated, "Authorization header is required")
	}

	return token, nil
}
