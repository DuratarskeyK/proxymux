package socks5protocol

import (
	"fmt"
	"net"
)

type Address struct {
	Type  byte
	Value []byte
	Port  uint16

	StrAddr         string
	StrAddrWithPort string
}

func (addr *Address) fillValues() {
	val := addr.Value
	switch addr.Type {
	case IPv4Address, IPv6Address:
		addr.StrAddr = net.IP(val).String()
	case HostnameAddress:
		addr.StrAddr = string(val)
	}
	if addr.Type == IPv6Address {
		addr.StrAddrWithPort = fmt.Sprintf("[%s]:%d", addr.StrAddr, addr.Port)
	} else {
		addr.StrAddrWithPort = fmt.Sprintf("%s:%d", addr.StrAddr, addr.Port)
	}
}
