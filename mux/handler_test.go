package mux

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/duratarskeyk/proxymux/corestructs"
	"github.com/duratarskeyk/proxymux/httpprotocol"
	"github.com/duratarskeyk/proxymux/socks4protocol"
	"github.com/duratarskeyk/proxymux/socks5protocol"
)

type handlers struct {
	socks4Called bool
	socks5Called bool
	httpCalled   bool

	exitHandlerCalled bool
	doneCh            chan struct{}
}

func (h *handlers) socks4(ctx context.Context, req *socks4protocol.Socks4Request) {
	h.socks4Called = true
}

func (h *handlers) socks5(ctx context.Context, req *socks5protocol.Socks5Request) {
	h.socks5Called = true
}

func (h *handlers) http(ctx context.Context, req *httpprotocol.HTTPRequest) {
	h.httpCalled = true
}

func (h *handlers) exit(c net.Conn) {
	h.exitHandlerCalled = true
	h.doneCh <- struct{}{}
}

func TestHandler(t *testing.T) {
	h := &handlers{doneCh: make(chan struct{})}
	mux := Handler{
		SOCKS4Handler: h.socks4,
		SOCKS5Handler: h.socks5,
		HTTPHandler:   h.http,
		ExitHandler:   h.exit,
		Timeouts:      &corestructs.Timeouts{Handshake: 30 * time.Second},
	}

	firstBytes := []byte{4, 5, 'G', 255}
	results := [][]bool{
		{true, false, false, true},
		{false, true, false, true},
		{false, false, true, true},
		{false, false, false, true},
	}
	for nr, v := range firstBytes {
		h.httpCalled = false
		h.socks4Called = false
		h.socks5Called = false
		h.exitHandlerCalled = false
		c1, c2 := net.Pipe()
		go mux.Handle(context.Background(), c1, nil, nil, nil, "1.1.1.1", "2.2.2.2")
		c2.Write([]byte{v})
		<-h.doneCh
		if results[nr][0] != h.socks4Called {
			t.Errorf("Test %d: Expected socks4Called to be %v, got %v", nr+1, results[nr][0], h.socks4Called)
		}
		if results[nr][1] != h.socks5Called {
			t.Errorf("Test %d: Expected socks5Called to be %v, got %v", nr+1, results[nr][1], h.socks4Called)
		}
		if results[nr][2] != h.httpCalled {
			t.Errorf("Test %d: Expected httpCalled to be %v, got %v", nr+1, results[nr][2], h.socks4Called)
		}
		if results[nr][3] != h.exitHandlerCalled {
			t.Errorf("Test %d: Expected exitHandlerCalled to be %v, got %v", nr+1, results[nr][3], h.socks4Called)
		}
		c1.Close()
		c2.Close()
	}

	h.httpCalled = false
	h.socks4Called = false
	h.socks5Called = false
	h.exitHandlerCalled = false
	c1, c2 := net.Pipe()
	mux.Timeouts.Handshake = time.Second
	go mux.Handle(context.Background(), c1, nil, nil, nil, "1.1.1.1", "2.2.2.2")
	c1.Close()
	c2.Close()
	<-h.doneCh
	if false != h.socks4Called {
		t.Errorf("Test %d: Expected socks4Called to be %v, got %v", 5, false, h.socks4Called)
	}
	if false != h.socks5Called {
		t.Errorf("Test %d: Expected socks5Called to be %v, got %v", 5, false, h.socks4Called)
	}
	if false != h.httpCalled {
		t.Errorf("Test %d: Expected httpCalled to be %v, got %v", 5, false, h.socks4Called)
	}
	if true != h.exitHandlerCalled {
		t.Errorf("Test %d: Expected exitHandlerCalled to be %v, got %v", 5, true, h.socks4Called)
	}
}
