package socks5protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/duratarskeyk/go-common-utils/proxyconfig"
	"github.com/duratarskeyk/proxymux/corestructs"
)

func TestAuthorize(t *testing.T) {
	// test IPAuth handshake
	retChan := make(chan []byte)
	idChan := make(chan int)
	errChan := make(chan error)

	c1, c2 := net.Pipe()
	go func() {
		c2.Write([]byte{1, 0})
		ret := []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
	}()
	proxyConfig := &proxyconfig.Config{}
	json.Unmarshal([]byte("{\"ips_to_credentials\": {}, \"ips_to_authorized_ips\":{\"pipe\": {\"pipe\": 1}}}"), proxyConfig)
	req := &Socks5Request{
		Fields: &corestructs.Fields{
			Conn:        c1,
			ProxyConfig: proxyConfig,
			UserIP:      "pipe",
			ProxyIP:     "pipe",
		},
		handshakeConn: readWriter{conn: c1, timeout: 30 * time.Second},
	}
	err := authorize(req)
	if err != nil {
		t.Fatalf("Expected err to be nil, got %s", err)
	}
	if req.Fields.PackageID != 1 {
		t.Fatalf("Expected pkgID to be 1, got %d", req.Fields.PackageID)
	}
	ret := <-retChan
	if !bytes.Equal(ret, noAuth) {
		t.Fatalf("Expected noAuth to be returned")
	}
	c1.Close()
	c2.Close()

	// test CredentialsAuth handshake
	c1, c2 = net.Pipe()
	go func() {
		c2.Write([]byte{2, 0, 2})
		ret := []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
		c2.Write([]byte{1, 3, 'a', 'b', 'c', 4, 'd', 'e', 'f', 'g'})
		ret = []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
	}()
	go func() {
		proxyConfig := &proxyconfig.Config{}
		json.Unmarshal([]byte("{\"ips_to_credentials\": {\"pipe\": {\"abc:defg\": 1}}, \"ips_to_authorized_ips\": {}}"), proxyConfig)
		req := &Socks5Request{
			Fields: &corestructs.Fields{
				Conn:        c1,
				ProxyConfig: proxyConfig,
				UserIP:      "pipe",
				ProxyIP:     "pipe",
			},
			handshakeConn: readWriter{conn: c1, timeout: 30 * time.Second},
		}
		err := authorize(req)
		idChan <- req.Fields.PackageID
		errChan <- err
	}()
	ret = <-retChan
	if !bytes.Equal(ret, userPassAuth) {
		t.Fatalf("Unexpected response")
	}
	ret = <-retChan
	if !bytes.Equal(ret, authSuccess) {
		t.Log(ret)
		t.Fatal("Unexpected response")
	}
	id := <-idChan
	if id != 1 {
		t.Fatal("Expected pkgID to be 1")
	}
	err = <-errChan
	if err != nil {
		t.Fatalf("Expected err to be nil, got %s", err)
	}
	c1.Close()
	c2.Close()

	// test Bad Credentials Auth handshake
	c1, c2 = net.Pipe()
	go func() {
		c2.Write([]byte{2, 0, 2})
		ret := []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
		c2.Write([]byte{1, 3, 'a', 'b', 'c', 4, 'd', 'e', 'f', 'g'})
		ret = []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
	}()
	go func() {
		req := &Socks5Request{
			Fields: &corestructs.Fields{
				Conn:        c1,
				ProxyConfig: &proxyconfig.Config{},
				UserIP:      "pipe",
				ProxyIP:     "pipe",
			},
			handshakeConn: readWriter{conn: c1, timeout: 30 * time.Second},
		}
		err := authorize(req)
		idChan <- req.Fields.PackageID
		errChan <- err
	}()
	ret = <-retChan
	if !bytes.Equal(ret, userPassAuth) {
		t.Fatalf("Unexpected response")
	}
	ret = <-retChan
	if !bytes.Equal(ret, authFailure) {
		t.Fatal("Unexpected response")
	}
	id = <-idChan
	if id != 0 {
		t.Fatal("Expected pkgID to be 0")
	}
	err = <-errChan
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("Expected err to be ErrBadCredentials, got %s", err)
	}
	c1.Close()
	c2.Close()

	// test no acceptable method handshake
	c1, c2 = net.Pipe()
	go func() {
		c2.Write([]byte{1, 0})
		ret := []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
	}()
	req = &Socks5Request{
		Fields: &corestructs.Fields{
			Conn:        c1,
			ProxyConfig: &proxyconfig.Config{},
			UserIP:      "pipe",
			ProxyIP:     "pipe",
		},
		handshakeConn: readWriter{conn: c1, timeout: 30 * time.Second},
	}
	err = authorize(req)
	ret = <-retChan
	if !bytes.Equal(ret, noAcceptable) {
		t.Fatalf("Expected no acceptable auth to be returned")
	}
	if req.Fields.PackageID != 0 {
		t.Fatalf("Expected pkgID to be 0, got %d", req.Fields.PackageID)
	}
	if !errors.Is(err, ErrNoAcceptableAuthMethod) {
		t.Fatalf("Expected err to be ErrNoAcceptableAuthMethod, got %s", err)
	}
	c1.Close()
	c2.Close()

	// IP auth, but no auth is not offered
	c1, c2 = net.Pipe()
	go func() {
		c2.Write([]byte{1, 2})
		ret := []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
		c2.Write([]byte{1, 3, 'a', 'b', 'c', 4, 'd', 'e', 'f', 'g'})
		ret = []byte{0, 0}
		c2.Read(ret)
		retChan <- ret
	}()
	go func() {
		proxyConfig := &proxyconfig.Config{}
		json.Unmarshal([]byte("{\"ips_to_credentials\": {}, \"ips_to_authorized_ips\":{\"pipe\": {\"pipe\": 1}}}"), proxyConfig)
		req := &Socks5Request{
			Fields: &corestructs.Fields{
				Conn:        c1,
				ProxyConfig: proxyConfig,
				UserIP:      "pipe",
				ProxyIP:     "pipe",
			},
			handshakeConn: readWriter{conn: c1, timeout: 30 * time.Second},
		}
		err := authorize(req)
		idChan <- req.Fields.PackageID
		errChan <- err
	}()
	ret = <-retChan
	if !bytes.Equal(ret, userPassAuth) {
		t.Fatalf("Unexpected response")
	}
	ret = <-retChan
	if !bytes.Equal(ret, authSuccess) {
		t.Fatal("Unexpected response")
	}
	id = <-idChan
	if id != 1 {
		t.Fatal("Expected pkgID to be 1")
	}
	err = <-errChan
	if err != nil {
		t.Fatalf("Expected err to be nil, got %s", err)
	}
	c1.Close()
	c2.Close()
}
