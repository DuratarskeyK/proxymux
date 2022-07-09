package socks5protocol

import (
	"errors"
	"fmt"
)

var ErrVersionMismatch = errors.New("wrong socks version")
var ErrUserAuthVersionMismatch = errors.New("user auth version mismatch")
var ErrBadCredentials = errors.New("bad credentials")
var ErrNoAcceptableAuthMethod = errors.New("no acceptable auth method")
var ErrUnknownAddressType = errors.New("unknown address type")
var ErrUnkownCommand = errors.New("unknown command code received")
var ErrSliceTooShort = errors.New("slice is too short")
var ErrNoAuthMethodsOffered = errors.New("no auth methods offered")

type ErrAuthFailure struct {
	err error
}

func (e *ErrAuthFailure) Error() string {
	return fmt.Sprintf("SOCKS5 authorization error: %s", e.err)
}

func (e *ErrAuthFailure) Unwrap() error {
	return e.err
}

type ErrCommandReadFailure struct {
	err error
}

func (e *ErrCommandReadFailure) Error() string {
	return fmt.Sprintf("SOCKS5 command packet read error: %s", e.err)
}

func (e *ErrCommandReadFailure) Unwrap() error {
	return e.err
}
