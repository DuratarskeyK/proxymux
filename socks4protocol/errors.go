package socks4protocol

import "errors"

var ErrUnsuportedCommand = errors.New("unsupported command")
var ErrBadCredentials = errors.New("ip and credentials auth failed")
var ErrIPAuthFailed = errors.New("ip auth failed")

type ErrBadRequest struct {
	err error
}

func (e *ErrBadRequest) Error() string {
	return "SOCKS4 request error: " + e.err.Error()
}

func (e *ErrBadRequest) Unwrap() error {
	return e.err
}

type ErrAuthorization struct {
	err error
}

func (e *ErrAuthorization) Error() string {
	return "SOCKS4 authorization error: " + e.err.Error()
}

func (e *ErrAuthorization) Unwrap() error {
	return e.err
}
