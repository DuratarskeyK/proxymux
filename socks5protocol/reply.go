package socks5protocol

import (
	"github.com/duratarskeyk/go-common-utils/idlenet"
)

func SendSuccessReply(req *Socks5Request, addr *Address) error {
	switch addr.Type {
	case IPv4Address:
		_, err := idlenet.WriteWithTimeout(req.Fields.Conn, req.Fields.Timeouts.Write, []byte{
			socks5Version,
			SuccessReply,
			0,
			IPv4Address,
			addr.Value[0],
			addr.Value[1],
			addr.Value[2],
			addr.Value[3],
			byte(addr.Port >> 8),
			byte(addr.Port & 0xFF),
		})
		return err
	case IPv6Address:
		_, err := idlenet.WriteWithTimeout(req.Fields.Conn, req.Fields.Timeouts.Write,
			[]byte{socks5Version, SuccessReply, 0, IPv6Address,
				addr.Value[0], addr.Value[1], addr.Value[2], addr.Value[3],
				addr.Value[4], addr.Value[5], addr.Value[6], addr.Value[7],
				addr.Value[8], addr.Value[9], addr.Value[10], addr.Value[11],
				addr.Value[12], addr.Value[13], addr.Value[14], addr.Value[15],
				byte(addr.Port >> 8), byte(addr.Port & 0xFF),
			})
		return err
	}

	return ErrUnknownAddressType
}

func SendFailReply(req *Socks5Request, replyCode byte) error {
	_, err := idlenet.WriteWithTimeout(
		req.Fields.Conn,
		req.Fields.Timeouts.Write,
		[]byte{socks5Version, replyCode, 0, 1, 0, 0, 0, 0, 0, 0},
	)
	return err
}
