package socks5protocol

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/duratarskeyk/go-common-utils/proxyconfig"
	"github.com/duratarskeyk/proxymux/corestructs"
)

type goodTestCase struct {
	proxyConfig []byte
	authMethods []byte
	authProcess []byte
	command     []byte

	commandCode byte
	host        string
	port        string
	packageID   int
	userID      int
	systemUser  bool
	backconnect bool
}

func TestGoodRequests(t *testing.T) {
	var testCases = []*goodTestCase{
		{
			[]byte(`{"package_ids_to_user_ids": {"1": 11}, "ips_to_credentials": {}, "ips_to_authorized_ips":{"1.2.3.4": {"4.3.2.1": 1}}}`),
			[]byte{2, 0, 2},
			nil,
			[]byte{5, 1, 0, 1, 2, 2, 2, 2, 0, 78},
			1,
			"2.2.2.2",
			"78",
			1,
			11,
			false,
			false,
		},
		{
			[]byte(`{"backconnect_user": "a:b", "all_access": {"a:b": true}, "ips_to_credentials": {}, "ips_to_authorized_ips":{}}`),
			[]byte{2, 0, 2},
			[]byte{1, 1, 'a', 1, 'b'},
			[]byte{5, 1, 0, 1, 2, 2, 2, 2, 0, 78, 0, 0, 0, 2, 0, 0, 0, 22, 5, 5, 5, 5},
			1,
			"2.2.2.2",
			"78",
			2,
			22,
			false,
			true,
		},
	}
	for nr, testCase := range testCases {
		c1, c2 := net.Pipe()
		req := GetSocks5Request()
		var cfg proxyconfig.Config
		json.Unmarshal(testCase.proxyConfig, &cfg)
		fields := req.Fields
		fields.UserIP = "4.3.2.1"
		fields.ProxyIP = "1.2.3.4"
		fields.PackageID = 0
		fields.UserID = 0
		fields.Conn = c1
		fields.ProxyConfig = &cfg
		fields.Timeouts = &corestructs.Timeouts{Handshake: 30 * time.Second}
		var wg sync.WaitGroup
		wg.Add(1)
		go func(r *Socks5Request, w *sync.WaitGroup) {
			defer w.Done()
			req.Read()
		}(req, &wg)
		c2.Write(testCase.authMethods)
		c2.Read([]byte{0, 0})
		if testCase.authProcess != nil {
			c2.Write(testCase.authProcess)
			result := []byte{0, 0}
			c2.Read(result)
			if result[1] != authSuccessStatus {
				t.Error("User-pass auth failed")
			}
		}
		c2.Write(testCase.command)
		wg.Wait()
		if req.Fields.Host != testCase.host {
			t.Errorf("Test #%d: Bad host: %s != %s\n", nr+1, req.Fields.Host, testCase.host)
		}
		if req.Fields.Port != testCase.port {
			t.Errorf("Test #%d: Bad port: %s != %s\n", nr+1, req.Fields.Port, testCase.port)
		}
		if req.Command != testCase.commandCode {
			t.Errorf("Test #%d: Command doesn't match: %d != %d\n", nr+1, req.Command, testCase.commandCode)
		}
		if req.Fields.PackageID != testCase.packageID {
			t.Errorf("Test #%d: Bad package id: %d != %d\n", nr+1, req.Fields.PackageID, testCase.packageID)
		}
		if req.Fields.UserID != testCase.userID {
			t.Errorf("Test #%d: Bad user id: %d != %d\n", nr+1, req.Fields.UserID, testCase.userID)
		}
		if req.Fields.SystemUser != testCase.systemUser {
			t.Errorf("Test #%d: SystemUser must be %v, got %v", nr+1, testCase.systemUser, req.Fields.SystemUser)
		}
		if req.Fields.Backconnect != testCase.backconnect {
			t.Errorf("Test #%d: Backconnect must be %v, got %v", nr+1, testCase.backconnect, req.Fields.Backconnect)
		}
		if req.Fields.Backconnect && req.Fields.UserIP != "5.5.5.5" {
			t.Errorf("Test #%d: Expected user ip to equal to 5.5.5.5, got %s", nr+1, req.Fields.UserIP)
		}
		PutSocks5Request(req)
		c1.Close()
		c2.Close()
	}
}

func TestBadRequests(t *testing.T) {
	// auth error
	// command error
	// backconnect error
	var cfg proxyconfig.Config
	json.Unmarshal([]byte(`{"package_ids_to_user_ids": {"1": 11}, "ips_to_credentials": {}, "ips_to_authorized_ips":{"1.2.3.4": {"4.3.2.1": 1}}}`), &cfg)
	c1, c2 := net.Pipe()
	req := GetSocks5Request()
	fields := req.Fields
	fields.UserIP = "4.3.2.1"
	fields.ProxyIP = "3.2.3.4"
	fields.PackageID = 0
	fields.UserID = 0
	fields.Conn = c1
	fields.ProxyConfig = &cfg
	fields.Timeouts = &corestructs.Timeouts{Handshake: 30 * time.Second}
	errCh := make(chan error)
	go func() {
		errCh <- req.Read()
	}()
	c2.Write([]byte{2, 0, 2})
	c2.Read([]byte{0, 0})
	c2.Write([]byte{1, 1, 'a', 1, 'b'})
	c2.Read([]byte{0, 0})
	err := <-errCh
	if !errors.Is(err, ErrBadCredentials) {
		t.Errorf("Test 1: Expected ErrBadCredentials, got %s", err)
	}
	PutSocks5Request(req)
	c1.Close()
	c2.Close()

	c1, c2 = net.Pipe()
	req = GetSocks5Request()
	fields = req.Fields
	fields.UserIP = "4.3.2.1"
	fields.ProxyIP = "1.2.3.4"
	fields.PackageID = 0
	fields.UserID = 0
	fields.Conn = c1
	fields.ProxyConfig = &cfg
	fields.Timeouts = &corestructs.Timeouts{Handshake: 30 * time.Second}
	go func() {
		errCh <- req.Read()
	}()
	c2.Write([]byte{1, 0})
	c2.Read([]byte{0, 0})
	c2.Write([]byte{5, 5, 0, 0})
	err = <-errCh
	if !errors.Is(err, ErrUnkownCommand) {
		t.Errorf("Test 2: Expected ErrUnkownCommand, got %s", err)
	}
	c1.Close()
	c2.Close()

	cfg = proxyconfig.Config{}
	json.Unmarshal([]byte(`{"backconnect_user": "a:b", "all_access": {"a:b": true}}`), &cfg)
	c1, c2 = net.Pipe()
	req = GetSocks5Request()
	fields = req.Fields
	fields.UserIP = "4.3.2.1"
	fields.ProxyIP = "1.2.3.4"
	fields.PackageID = 0
	fields.UserID = 0
	fields.Conn = c1
	fields.ProxyConfig = &cfg
	fields.Timeouts = &corestructs.Timeouts{Handshake: 1 * time.Second}
	go func() {
		errCh <- req.Read()
	}()
	c2.Write([]byte{1, 2})
	c2.Read([]byte{0, 0})
	c2.Write([]byte{1, 1, 'a', 1, 'b'})
	b := []byte{0, 0}
	c2.Read(b)
	c2.Write([]byte{5, 1, 0, 1, 2, 2, 2, 2, 0, 78, 0, 0})
	err = <-errCh
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Test 3: Expected ErrDeadlineExceeded, got %s", err)
	}
	c1.Close()
	c2.Close()
}
