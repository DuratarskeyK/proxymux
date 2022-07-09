package socks5protocol

import (
	"net"
	"strconv"

	"github.com/duratarskeyk/proxymux/corestructs"
)

func readAddress(req *Socks5Request, addrType byte) error {
	var err error
	if addrType == 0 {
		typeBuf := []byte{0}
		if _, err = req.handshakeConn.Read(typeBuf); err != nil {
			return err
		}
		addrType = typeBuf[0]
	}

	var addrBuf []byte
	var addrLength int
	switch addrType {
	case IPv4Address:
		addrLength = 6
		addrBuf = make([]byte, addrLength)
	case HostnameAddress:
		hostnameLength := []byte{0}
		if _, err = req.handshakeConn.Read(hostnameLength); err != nil {
			return err
		}
		addrLength = int(hostnameLength[0]) + 2
		addrBuf = make([]byte, addrLength)
	case IPv6Address:
		addrLength = 18
		addrBuf = make([]byte, addrLength)
	default:
		return ErrUnknownAddressType
	}
	if _, err = req.handshakeConn.Read(addrBuf); err != nil {
		return err
	}

	fields := req.Fields

	fields.PortNum = (uint16(addrBuf[addrLength-2]) << 8) | uint16(addrBuf[addrLength-1])
	fields.Port = strconv.Itoa(int(fields.PortNum))

	value := addrBuf[:addrLength-2]
	switch addrType {
	case IPv4Address, IPv6Address:
		if addrType == IPv4Address {
			fields.HostType = corestructs.HostTypeIPv4
		} else {
			fields.HostType = corestructs.HostTypeIPv6
		}
		fields.HostIP = net.IP(value)
		fields.Host = fields.HostIP.String()
	case HostnameAddress:
		fields.HostType = corestructs.HostTypeHostname
		fields.Host = string(value)
		fields.HostIP = nil
	}

	return nil
}
