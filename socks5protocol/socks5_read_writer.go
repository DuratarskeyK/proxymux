package socks5protocol

import (
	"net"
	"time"

	"github.com/duratarskeyk/go-common-utils/idlenet"
)

type readWriter struct {
	conn     net.Conn
	timeout  time.Duration
	upload   int64
	download int64
}

func (c *readWriter) Read(p []byte) (int, error) {
	n, err := idlenet.ReadWithTimeout(c.conn, c.timeout, p)
	c.upload += int64(n)
	return n, err
}

func (c *readWriter) Write(p []byte) (int, error) {
	n, err := idlenet.WriteWithTimeout(c.conn, c.timeout, p)
	c.download += int64(n)
	return n, err
}
