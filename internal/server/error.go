package server

import (
	"log"

	"github.com/ZeroLarec/zerolarec_server/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func processStorageErr(err error) error {
	st := toGRPCStatus(err)
	log.Printf("got error: %s: %s", st.Err(), err.Error())

	return st.Err()
}

func toGRPCStatus(err error) *status.Status {
	var (
		code    codes.Code
		message string
	)

	switch {
	case err == nil:
		return nil
	case storage.IsNotFoundError(err):
		code = codes.NotFound
		message = "not found"
	case storage.IsAlreadyExistsError(err):
		code = codes.AlreadyExists
		message = "already exists"
	case storage.IsBadRequestError(err):
		code = codes.InvalidArgument
		message = "bad request"
	case storage.IsNoAccessError(err):
		code = codes.PermissionDenied
		message = "no access"
	case storage.IsInternalError(err):
		code = codes.Internal
		message = "internal error"
	default:
		code = codes.Internal
		message = "unexpected internal error"
	}

	return status.New(code, message)
}
