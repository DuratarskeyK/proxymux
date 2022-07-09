package httpprotocol

import (
	"sync"

	"github.com/duratarskeyk/proxymux/corestructs"
	"go.uber.org/zap/zapcore"
)

var HTTPRequestPool = sync.Pool{}

func GetHTTPRequest() *HTTPRequest {
	req := HTTPRequestPool.Get()
	if req != nil {
		return req.(*HTTPRequest)
	}

	return &HTTPRequest{
		Fields: &corestructs.Fields{
			LogFields: make([]zapcore.Field, 0, 9),
		},
	}
}

func PutHTTPRequest(req *HTTPRequest) {
	req.Fields.Clean()
	req.handshakeConn.conn = nil
	req.Request = nil

	HTTPRequestPool.Put(req)
}
