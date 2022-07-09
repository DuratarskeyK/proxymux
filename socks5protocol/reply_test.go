package socks5protocol

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/duratarskeyk/proxymux/corestructs"
)

func TestSendSuccessReply(t *testing.T) {
	var tests = []*Address{
		{Type: IPv4Address, Value: []byte{1, 1, 1, 1}, Port: 53},
		{Type: IPv6Address, Value: []byte{255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 1, 2, 3, 4}, Port: 1234},
	}
	var testResults = []struct {
		Type int
		Host string
		Port uint16
	}{
		{corestructs.HostTypeIPv4, "1.1.1.1", 53},
		{corestructs.HostTypeIPv6, "ffff:ffff::ffff:ffff:102:304", 1234},
	}
	for nr, test := range tests {
		c1, c2 := net.Pipe()
		go func(conn net.Conn, addr *Address) {
			req := &Socks5Request{Fields: &corestructs.Fields{Conn: conn, Timeouts: &corestructs.Timeouts{Write: 30 * time.Second}}}
			SendSuccessReply(req, addr)
		}(c1, test)
		header := make([]byte, 3)
		c2.Read(header)
		if header[0] != socks5Version {
			t.Fatalf("Test %d: First byte must be %d", nr+1, socks5Version)
		}
		if header[1] != SuccessReply {
			t.Fatalf("Test %d: Second byte must be %d", nr+1, SuccessReply)
		}
		if header[2] != 0 {
			t.Fatalf("Test %d: Third byte must be 0", nr+1)
		}
		req2 := &Socks5Request{
			Fields: &corestructs.Fields{
				Conn: c2,
			},
			handshakeConn: readWriter{conn: c2, timeout: 30 * time.Second},
		}
		err := readAddress(req2, 0)
		if err != nil {
			t.Fatalf("Test %d: Expected err to be nil, got %s", nr+1, err)
		}
		if req2.Fields.HostType != testResults[nr].Type || req2.Fields.Host != testResults[nr].Host || req2.Fields.PortNum != testResults[nr].Port {
			t.Fatalf("Test %d: Read address doesn't match address in reply", nr+1)
		}
		c1.Close()
		c2.Close()
	}

	req := &Socks5Request{Fields: &corestructs.Fields{Conn: nil, Timeouts: &corestructs.Timeouts{Read: 30 * time.Second}}}
	if err := SendSuccessReply(req, &Address{Type: 44}); !errors.Is(err, ErrUnknownAddressType) {
		t.Fatalf("Expected err to be ErrUnknownAddressType, got %s", err)
	}
}

func TestSendFailReply(t *testing.T) {
	var response = []byte{socks5Version, 99, 0, 1, 0, 0, 0, 0, 0, 0}
	var replies = []byte{AddrTypeNotSupported, CommandNotSupported}
	for _, reply := range replies {
		c1, c2 := net.Pipe()
		req := &Socks5Request{Fields: &corestructs.Fields{Conn: c1, Timeouts: &corestructs.Timeouts{Write: 30 * time.Second}}}
		go func() {
			SendFailReply(req, reply)
		}()
		recv := make([]byte, 10)
		c2.Read(recv)
		response[1] = reply
		if !bytes.Equal(recv, response) {
			t.Errorf("Reply code doesn't match %d != %d", reply, recv[1])
		}
	}
}
