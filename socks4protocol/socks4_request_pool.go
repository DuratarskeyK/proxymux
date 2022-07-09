package socks4protocol

import (
	"sync"

	"github.com/duratarskeyk/proxymux/corestructs"
	"go.uber.org/zap/zapcore"
)

var socks4RequestPool = sync.Pool{}

func GetSocks4Request() *Socks4Request {
	req := socks4RequestPool.Get()
	if req != nil {
		return req.(*Socks4Request)
	}

	return &Socks4Request{
		Fields: &corestructs.Fields{
			LogFields: make([]zapcore.Field, 0, 9),
		},
	}
}

func PutSocks4Request(req *Socks4Request) {
	req.Fields.Clean()
	req.connWrapper.conn = nil

	socks4RequestPool.Put(req)
}
