package socks5protocol

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/duratarskeyk/proxymux/corestructs"
)

type addrTestResult struct {
	isAddr bool
	length int
	addr   *Address
	fields *corestructs.Fields
	err    error
}

func TestAddressFromSliceGood(t *testing.T) {
	goodAddrs := [][]byte{
		{1, 8, 8, 4, 4, 0, 53},
		{3, 5, 'y', 'a', '.', 'r', 'u', 0, 80},
		{4, 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x42, 0xC3, 0xFF, 0xFE, 0x55, 0xB6, 0x36, 1, 1},
	}
	goodAddrsStrAddrs := []string{
		"8.8.4.4",
		"ya.ru",
		"fe80::42:c3ff:fe55:b636",
	}
	goodTypes := []int{corestructs.HostTypeIPv4, corestructs.HostTypeHostname, corestructs.HostTypeIPv6}
	goodPorts := []uint16{53, 80, 257}
	goodAddrsStrAddrWithPorts := []string{
		"8.8.4.4:53",
		"ya.ru:80",
		"[fe80::42:c3ff:fe55:b636]:257",
	}
	addrLens := []int{
		7,
		9,
		19,
	}

	for test, v := range goodAddrs {
		var res []addrTestResult
		r, l, e := AddressFromSlice(v)

		c1, c2 := net.Pipe()
		go func(conn net.Conn, data []byte) {
			conn.Write(data)
		}(c1, v)
		req := &Socks5Request{Fields: &corestructs.Fields{Conn: c2}, handshakeConn: readWriter{conn: c2, timeout: 30 * time.Second}}
		e2 := readAddress(req, 0)
		r2 := req.Fields
		c1.Close()
		c2.Close()

		c1, c2 = net.Pipe()
		go func(conn net.Conn, data []byte) {
			conn.Write(data)
		}(c1, v[1:])
		req = &Socks5Request{Fields: &corestructs.Fields{Conn: c2}, handshakeConn: readWriter{conn: c2, timeout: 30 * time.Second}}
		e3 := readAddress(req, v[0])
		r3 := req.Fields
		c1.Close()
		c2.Close()

		res = append(res,
			addrTestResult{isAddr: true, length: l, addr: r, err: e},
			addrTestResult{isAddr: false, fields: r2, err: e2},
			addrTestResult{isAddr: false, fields: r3, err: e3},
		)
		for _, result := range res {
			if result.isAddr {
				addr, err := result.addr, result.err
				if err != nil {
					t.Errorf("Expected err to be nil, got %s", err)
					continue
				}
				if addr.Type != v[0] {
					t.Errorf("Addr type doesn't match")
					continue
				}
				cont := false
				switch addr.Type {
				case IPv4Address:
					for i := 0; i < 4; i++ {
						if v[1+i] != addr.Value[i] {
							t.Errorf("Address mismatch at %d", i)
							cont = true
							break
						}
					}
				case IPv6Address:
					for i := 0; i < 16; i++ {
						if v[1+i] != addr.Value[i] {
							t.Errorf("Address mismatch at %d", i)
							cont = true
							break
						}
					}
				case HostnameAddress:
					for i := 0; i < int(v[1]); i++ {
						if v[2+i] != addr.Value[i] {
							t.Errorf("Address mismatch at %d", i)
							cont = true
							break
						}
					}
				}
				if cont {
					continue
				}
				if goodPorts[test] != addr.Port {
					t.Errorf("Port mismatch %d != %d", goodPorts[test], addr.Port)
					continue
				}
				if goodAddrsStrAddrs[test] != addr.StrAddr {
					t.Errorf("StrAddr mismatch %s != %s", goodAddrsStrAddrs[test], addr.StrAddr)
					continue
				}
				if goodAddrsStrAddrWithPorts[test] != addr.StrAddrWithPort {
					t.Errorf("StrAddrWithPort mismatch %s != %s", goodAddrsStrAddrWithPorts[test], addr.StrAddrWithPort)
				}
				if addrLens[test] != result.length {
					t.Errorf("Returned address length mismatch %d != %d", addrLens[test], result.length)
				}
			} else {
				fields, err := result.fields, result.err
				if err != nil {
					t.Errorf("Expected err to be nil, got %s", err)
					continue
				}
				if fields.HostType != goodTypes[test] {
					t.Errorf("Type mismatch, %d != %d", fields.HostType, goodTypes[test])
					continue
				}
				if fields.Host != goodAddrsStrAddrs[test] {
					t.Errorf("Host mismatch: %s != %s", fields.Host, goodAddrsStrAddrs[test])
					continue
				}
				if fields.PortNum != goodPorts[test] {
					t.Errorf("Port mismatch, %d != %d", fields.PortNum, goodPorts[test])
				}
			}
		}
	}
}

func TestAddressFromSliceBad(t *testing.T) {
	shortAddrs := [][]byte{
		{},
		{1, 1, 1, 1, 1},
		{4, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		{3},
		{3, 5, 'a', 'b'},
	}

	var c1, c2 net.Conn
	for _, v := range shortAddrs {
		c1, c2 = net.Pipe()
		if _, _, err := AddressFromSlice(v); !errors.Is(err, ErrSliceTooShort) {
			t.Errorf("Expected err to be ErrSliceTooShort")
		}
		if len(v) > 0 {
			go func(conn net.Conn, data []byte) {
				conn.Write(data)
			}(c1, v)
		}
		req := &Socks5Request{Fields: &corestructs.Fields{Conn: c2}, handshakeConn: readWriter{conn: c2, timeout: 100 * time.Millisecond}}
		if err := readAddress(req, 0); err == nil {
			t.Errorf("Expected err to not be nil")
		}
		c1.Close()
		c2.Close()
	}
	if _, _, err := AddressFromSlice([]byte{55}); !errors.Is(err, ErrUnknownAddressType) {
		t.Errorf("Expected err to be ErrUnknownAddressType")
	}
	c1, c2 = net.Pipe()
	go func() {
		c1.Write([]byte{23})
	}()
	req := &Socks5Request{Fields: &corestructs.Fields{Conn: c2}, handshakeConn: readWriter{conn: c2, timeout: 30 * time.Millisecond}}
	if err := readAddress(req, 0); !errors.Is(err, ErrUnknownAddressType) {
		t.Errorf("Expected err to be ErrUnknownAddressType")
	}
	c1.Close()
	c2.Close()
}
