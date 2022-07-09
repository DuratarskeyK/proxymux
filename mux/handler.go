package mux

import (
	"context"
	"net"

	"github.com/duratarskeyk/go-common-utils/idlenet"
	"github.com/duratarskeyk/proxymux/corestructs"
	"github.com/duratarskeyk/proxymux/httpprotocol"
	"github.com/duratarskeyk/proxymux/socks4protocol"
	"github.com/duratarskeyk/proxymux/socks5protocol"
)

type Handler struct {
	SOCKS4Handler func(ctx context.Context, req *socks4protocol.Socks4Request)
	SOCKS5Handler func(ctx context.Context, req *socks5protocol.Socks5Request)
	HTTPHandler   func(ctx context.Context, req *httpprotocol.HTTPRequest)
	ExitHandler   func(conn net.Conn)

	Timeouts *corestructs.Timeouts
}

func (h Handler) Handle(
	ctx context.Context,
	conn net.Conn,
	dialerTCP *net.Dialer, dialerUDP *net.Dialer,
	proxyConfig interface{},
	proxyIP, userIP string,
) {
	f := []byte{0}
	_, err := idlenet.ReadWithTimeout(conn, h.Timeouts.Handshake, f)
	if err != nil {
		h.ExitHandler(conn)
		return
	}

	firstByte := f[0]
	if firstByte == 5 {
		req := socks5protocol.GetSocks5Request()
		fields := req.Fields
		fields.Conn = conn
		fields.ProxyConfig = proxyConfig
		fields.DialerTCP = dialerTCP
		fields.DialerUDP = dialerUDP
		fields.Timeouts = h.Timeouts
		fields.UserIP = userIP
		fields.ProxyIP = proxyIP
		proxyConfig = nil

		h.SOCKS5Handler(ctx, req)
		socks5protocol.PutSocks5Request(req)
	} else if firstByte == 4 {
		req := socks4protocol.GetSocks4Request()
		fields := req.Fields
		fields.Conn = conn
		fields.ProxyConfig = proxyConfig
		fields.DialerTCP = dialerTCP
		fields.Timeouts = h.Timeouts
		fields.UserIP = userIP
		fields.ProxyIP = proxyIP
		proxyConfig = nil

		h.SOCKS4Handler(ctx, req)
		socks4protocol.PutSocks4Request(req)
	} else if 'A' <= firstByte && firstByte <= 'Z' {
		req := httpprotocol.GetHTTPRequest()
		req.FirstByte = firstByte

		fields := req.Fields
		fields.Conn = conn
		fields.ProxyConfig = proxyConfig
		fields.DialerTCP = dialerTCP
		fields.Timeouts = h.Timeouts
		fields.UserIP = userIP
		fields.ProxyIP = proxyIP
		proxyConfig = nil

		h.HTTPHandler(ctx, req)
		httpprotocol.PutHTTPRequest(req)
	}
	h.ExitHandler(conn)
}
