package socks5protocol

import (
	"sync"

	"github.com/duratarskeyk/proxymux/corestructs"
	"go.uber.org/zap/zapcore"
)

var socks5RequestPool = sync.Pool{}

func GetSocks5Request() *Socks5Request {
	req := socks5RequestPool.Get()
	if req != nil {
		return req.(*Socks5Request)
	}

	return &Socks5Request{
		Fields: &corestructs.Fields{
			LogFields: make([]zapcore.Field, 0, 9),
		},
	}
}

func PutSocks5Request(req *Socks5Request) {
	req.Fields.Clean()
	req.handshakeConn.conn = nil

	socks5RequestPool.Put(req)
}
