package server

import (
	"context"

	apiv1 "github.com/ZeroLarec/zerolarec_server/api/proto/generated/v1"
)

func (s *Server) Check(ctx context.Context, req *apiv1.CheckRequest) (*apiv1.CheckResponse, error) {
	return &apiv1.CheckResponse{}, nil
}
