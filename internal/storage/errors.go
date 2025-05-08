package storage

import (
	"errors"
	"fmt"
)

type NoAccessError struct {
	err error
}

func NewNoAccessError(err error) *NoAccessError {
	return &NoAccessError{
		err: err,
	}
}

func (e *NoAccessError) Error() string {
	return fmt.Sprintf("no access: %s", e.err.Error())
}

func IsNoAccessError(err error) bool {
	var e *NoAccessError
	return errors.As(err, &e)
}

type InternalError struct {
	err error
}

func NewInternalError(err error) *InternalError {
	return &InternalError{
		err: err,
	}
}

func (e *InternalError) Error() string {
	return fmt.Sprintf("internal error: %s", e.err.Error())
}

func IsInternalError(err error) bool {
	var e *InternalError
	return errors.As(err, &e)
}

type NotFoundError struct {
	err error
}

func NewNotFoundError(err error) *NotFoundError {
	return &NotFoundError{
		err: err,
	}
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("not found: %s", e.err.Error())
}

func IsNotFoundError(err error) bool {
	var e *NotFoundError
	return errors.As(err, &e)
}

type BadRequestError struct {
	err error
}

func NewBadRequestError(err error) *BadRequestError {
	return &BadRequestError{
		err: err,
	}
}

func (e *BadRequestError) Error() string {
	return fmt.Sprintf("bad request: %s", e.err.Error())
}

func IsBadRequestError(err error) bool {
	var e *BadRequestError
	return errors.As(err, &e)
}

type AlreadyExistsError struct {
	err error
}

func NewAlreadyExistsError(err error) *AlreadyExistsError {
	return &AlreadyExistsError{
		err: err,
	}
}

func (e *AlreadyExistsError) Error() string {
	return fmt.Sprintf("already exists: %s", e.err.Error())
}

func IsAlreadyExistsError(err error) bool {
	var e *AlreadyExistsError
	return errors.As(err, &e)
}
