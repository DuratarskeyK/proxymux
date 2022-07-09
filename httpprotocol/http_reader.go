package httpprotocol

import (
	"errors"
	"io"
	"net"
	"os"
	"time"
)

type httpReader struct {
	conn          net.Conn
	timeout       time.Duration
	firstByte     byte
	firstByteRead bool
	total         int64
}

var nilTime time.Time

func (c *httpReader) Read(p []byte) (int, error) {
	skip := false
	if !c.firstByteRead {
		p[0] = c.firstByte
		c.firstByteRead = true
		skip = true
	}
	c.conn.SetReadDeadline(time.Now().Add(c.timeout))
	defer c.conn.SetReadDeadline(nilTime)
	var (
		n   int
		err error
	)
	if skip {
		n, err = c.conn.Read(p[1:])
		n++
	} else {
		n, err = c.conn.Read(p)
	}
	c.total += int64(n)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		if n == 0 {
			return n, io.ErrUnexpectedEOF
		}

		return n, nil
	}
	return n, err
}
