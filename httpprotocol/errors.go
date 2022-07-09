package httpprotocol

import (
	"errors"
	"fmt"
)

var ErrRequestReadFailed = errors.New("failed to read http request")
var ErrNotAuthorativeRequest = errors.New("not authorative request")
var ErrUnknownScheme = errors.New("unknown scheme")
var ErrBadPort = errors.New("bad port")
var ErrIPv6Addr = errors.New("ipv6 address as host")
var ErrNotBasicAuth = errors.New("not basic auth")
var ErrBadCredentials = errors.New("bad credentials")
var ErrBackconnectUserIPNotPresent = errors.New("no user ip provided in a backconnect request")
var ErrIPAuthFailed = errors.New("ip auth failed, no credentials provided")

type ErrBadRequest struct {
	err error
}

func (e *ErrBadRequest) Error() string {
	return fmt.Sprintf("HTTP bad request: %s", e.err)
}

func (e *ErrBadRequest) Unwrap() error {
	return e.err
}

type ErrAuth struct {
	err error
}

func (e *ErrAuth) Error() string {
	return fmt.Sprintf("HTTP authorization error: %s", e.err)
}

func (e *ErrAuth) Unwrap() error {
	return e.err
}
