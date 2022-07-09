package socks4protocol

import (
	"errors"
	"io"
	"net"
	"os"
	"time"
)

type reader struct {
	conn        net.Conn
	readTimeout time.Duration
	total       int64
}

func (r *reader) Read(p []byte) (int, error) {
	r.conn.SetReadDeadline(time.Now().Add(r.readTimeout))
	n, err := r.conn.Read(p)
	r.total += int64(n)
	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		if n == 0 {
			return n, io.ErrUnexpectedEOF
		}

		return n, nil
	}
	return n, err
}
