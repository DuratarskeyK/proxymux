package socks5protocol

import (
	"net"
	"testing"
	"time"

	"github.com/duratarskeyk/proxymux/corestructs"
)

type commandTest struct {
	socksVersion byte
	cmd          byte
	addr         *Address
	err          bool
}

type commandTestResult struct {
	AddrType int
	Host     string
	Port     uint16
}

func TestReadCommand(t *testing.T) {
	var tests = []*commandTest{
		{socks5Version, ConnectCommand, &Address{Type: IPv4Address, Value: []byte{1, 1, 1, 1}, Port: 53}, false},
		{4, ConnectCommand, &Address{Type: IPv4Address, Value: []byte{1, 1, 1, 1}, Port: 53}, true},
		{socks5Version, 5, &Address{Type: IPv4Address, Value: []byte{1, 1, 1, 1}, Port: 53}, true},
		{socks5Version, ConnectCommand, &Address{Type: 69, Value: []byte{1, 1, 1, 1}, Port: 53}, true},
	}
	var testResults = []*commandTestResult{
		{corestructs.HostTypeIPv4, "1.1.1.1", 53},
		nil,
		nil,
		nil,
	}
	for nr, test := range tests {
		c1, c2 := net.Pipe()
		go func(conn net.Conn, test *commandTest) {
			conn.Write([]byte{test.socksVersion, test.cmd, 0})
			conn.Write([]byte{test.addr.Type})
			if test.addr.Type == HostnameAddress {
				conn.Write([]byte{byte(len(test.addr.Value))})
			}
			conn.Write(test.addr.Value)
			conn.Write([]byte{byte(test.addr.Port >> 8), byte(test.addr.Port & 0xFF)})
		}(c1, test)
		req := &Socks5Request{Fields: &corestructs.Fields{}, handshakeConn: readWriter{conn: c2, timeout: 30 * time.Second}}
		err := readCommand(req)
		if !test.err && err != nil {
			t.Fatalf("Test %d: Expected err to be nil, got %s", nr+1, err)
		}
		if test.err && err == nil {
			t.Fatalf("Test %d: Expected err to not be nil, got nil", nr+1)
		}
		if test.err && err != nil {
			c1.Close()
			c2.Close()
			continue
		}
		if req.Command != ConnectCommand {
			t.Fatalf("Test %d: Expected command to be %d", nr+1, ConnectCommand)
		}
		if req.Fields.HostType != testResults[nr].AddrType || req.Fields.Host != testResults[nr].Host || req.Fields.PortNum != testResults[nr].Port {
			t.Fatalf("Test %d: Address read != address written", nr+1)
		}
		c1.Close()
		c2.Close()
	}
	c1, c2 := net.Pipe()
	go func() {
		c1.Write([]byte{socks5Version, 0, 0})
	}()
	req := &Socks5Request{handshakeConn: readWriter{conn: c2, timeout: 100 * time.Millisecond}}
	if err := readCommand(req); err == nil {
		t.Fatalf("Expected err to not be nil, got nil")
	}
}
