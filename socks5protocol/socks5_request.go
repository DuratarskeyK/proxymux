package socks5protocol

import (
	"fmt"
	"net"

	"github.com/duratarskeyk/proxymux/corestructs"
	"go.uber.org/zap"
)

type Socks5Request struct {
	Fields *corestructs.Fields

	handshakeConn readWriter

	Command byte
}

func (req *Socks5Request) Read() error {
	fields := req.Fields
	req.handshakeConn.conn = fields.Conn
	req.handshakeConn.timeout = fields.Timeouts.Handshake
	req.handshakeConn.download = 0
	req.handshakeConn.upload = 0
	fields.Backconnect = false
	fields.LogFields = append(fields.LogFields,
		zap.String("user_ip", fields.UserIP),
		zap.String("proxy_ip", fields.ProxyIP),
		zap.String("type", "SOCKS5"),
	)

	err := authorize(req)
	if err != nil {
		return &ErrAuthFailure{err: err}
	}

	err = readCommand(req)
	if err != nil {
		return &ErrCommandReadFailure{err: err}
	}

	if req.Fields.Backconnect {
		backconnectData := make([]byte, 12)
		if _, err := req.handshakeConn.Read(backconnectData); err != nil {
			return &ErrCommandReadFailure{err: err}
		}
		packageID := uint(backconnectData[0])<<24 | uint(backconnectData[1])<<16 | uint(backconnectData[2])<<8 | uint(backconnectData[3])
		userID := uint(backconnectData[4])<<24 | uint(backconnectData[5])<<16 | uint(backconnectData[6])<<8 | uint(backconnectData[7])
		req.Fields.PackageID = int(packageID)
		req.Fields.UserID = int(userID)
		req.Fields.UserIP = fmt.Sprintf("%d.%d.%d.%d", backconnectData[8], backconnectData[9], backconnectData[10], backconnectData[11])
		req.Fields.LogFields[0].String = req.Fields.UserIP
	}

	fields.FillLogFields()

	fields.Download = req.handshakeConn.download
	fields.Upload = req.handshakeConn.upload + 1 // first byte 5

	proxyIPOctets := []byte(net.ParseIP(fields.ProxyIP).To4())
	fields.ProxyIPNum = (uint32(proxyIPOctets[0]) << 24) | (uint32(proxyIPOctets[1]) << 16) |
		(uint32(proxyIPOctets[2]) << 8) | uint32(proxyIPOctets[3])

	return nil
}
