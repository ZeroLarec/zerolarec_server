package server

import (
	"context"
	"log"
	"net"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type Config struct {
	Addr   string
	Secret string
}

type Server struct {
	apiv1.UnimplementedHealthServiceServer
	apiv1.UnimplementedUserServiceServer
	apiv1.UnimplementedVaultServiceServer
	apiv1.UnimplementedAccessRuleServiceServer
	apiv1.UnimplementedSecretServiceServer
	apiv1.UnimplementedAuthenticateServiceServer

	cfg Config

	grpcServer *grpc.Server
	store      storage.Storage
}

func NewLoggerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		log.Printf("method: %s, req: %v", info.FullMethod, req)
		return handler(ctx, req)
	}
}

func NewServer(cfg Config, store storage.Storage) (*Server, error) {
	s := &Server{
		cfg: cfg,
		grpcServer: grpc.NewServer(
			grpc.ChainUnaryInterceptor(
				NewAuthInterceptor([]byte(cfg.Secret)),
				NewLoggerInterceptor(),
			),
		),
		store: store,
	}

	apiv1.RegisterHealthServiceServer(s.grpcServer, s)
	apiv1.RegisterUserServiceServer(s.grpcServer, s)
	apiv1.RegisterVaultServiceServer(s.grpcServer, s)
	apiv1.RegisterAccessRuleServiceServer(s.grpcServer, s)
	apiv1.RegisterSecretServiceServer(s.grpcServer, s)
	apiv1.RegisterAuthenticateServiceServer(s.grpcServer, s)
	reflection.Register(s.grpcServer)

	return s, nil
}

func (s *Server) Run() error {
	lis, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}

	return s.grpcServer.Serve(lis)
}
