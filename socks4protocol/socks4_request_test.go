package socks4protocol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/duratarskeyk/go-common-utils/authorizer"
	"github.com/duratarskeyk/proxymux/corestructs"
	"github.com/duratarskeyk/proxymux/internal/authmock"
)

type goodTestCase struct {
	request     []byte
	authMock    *authmock.Mock
	host        string
	port        string
	packageID   int
	userID      int
	systemUser  bool
	backconnect bool
}

func TestGoodRequests(t *testing.T) {
	// ip auth + socks4
	// identd auth + socks4
	// ip auth + socks4a
	// identd auth + socks4a
	// backconnect + socks4a
	// systemuser + socks4a
	var testCases = []*goodTestCase{
		{
			[]byte{1, 0, 22, 212, 15, 134, 65, 0},
			&authmock.Mock{
				IPAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 1,
					UserID:    11,
				},
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			"212.15.134.65",
			"22",
			1,
			11,
			false,
			false,
		},
		{
			[]byte{1, 0, 80, 75, 15, 13, 65, 't', 'e', 's', 't', '.', 't', 'e', 's', 't', 0},
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 2,
					UserID:    22,
				},
			},
			"75.15.13.65",
			"80",
			2,
			22,
			false,
			false,
		},
		{
			[]byte{1, 21, 56, 0, 0, 0, 13, 0, 'y', 'a', '.', 'r', 'u', 0},
			&authmock.Mock{
				IPAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 3,
					UserID:    33,
				},
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			"ya.ru",
			"5432",
			3,
			33,
			false,
			false,
		},
		{
			[]byte{1, 0, 80, 0, 0, 0, 65, 't', 'e', 's', 't', '.', 't', 'e', 's', 't', 0, 'y', 'y', '.', 'r', 'u', 0},
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 4,
					UserID:    44,
				},
			},
			"yy.ru",
			"80",
			4,
			44,
			false,
			false,
		},
		{
			[]byte{1, 0, 99, 0, 0, 0, 33, 'a', '.', 'b', 0, 'e', 'x', '.', 'r', 'u', 0, 0, 0, 0, 5, 0, 0, 0, 55, 5, 5, 5, 5},
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:          true,
					PackageID:   5,
					UserID:      55,
					Backconnect: true,
				},
			},
			"ex.ru",
			"99",
			5,
			55,
			false,
			true,
		},
		{
			[]byte{1, 0, 99, 0, 0, 0, 33, 'a', '.', 'b', 0, 'e', 'x', '.', 'r', 'u', 0},
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:         true,
					SystemUser: true,
				},
			},
			"ex.ru",
			"99",
			0,
			0,
			true,
			false,
		},
	}
	for nr, testCase := range testCases {
		c1, c2 := net.Pipe()
		req := GetSocks4Request()
		fields := req.Fields
		fields.UserIP = "4.3.2.1"
		fields.ProxyIP = "1.2.3.4"
		fields.PackageID = 0
		fields.UserID = 0
		fields.Conn = c1
		fields.ProxyConfig = testCase.authMock
		fields.Timeouts = &corestructs.Timeouts{Handshake: 30 * time.Second}
		var wg sync.WaitGroup
		wg.Add(2)
		go func(conn net.Conn, data []byte, w *sync.WaitGroup) {
			defer w.Done()
			conn.Write(data)
		}(c2, testCase.request, &wg)
		go func(r *Socks4Request, w *sync.WaitGroup) {
			defer w.Done()
			req.Read()
		}(req, &wg)
		wg.Wait()
		if req.Fields.Host != testCase.host {
			t.Errorf("Test #%d: Bad host: %s != %s\n", nr+1, req.Fields.Host, testCase.host)
		}
		if req.Fields.Port != testCase.port {
			t.Errorf("Test #%d: Bad port: %s != %s\n", nr+1, req.Fields.Port, testCase.port)
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
		PutSocks4Request(req)
		c1.Close()
		c2.Close()
	}
}

func TestBadRequests(t *testing.T) {
	badRequests := [][]byte{
		{1, 0, 0},
		{2, 0, 22, 1, 2, 3, 4, 0},
		append([]byte{1, 0, 22, 1, 2, 3, 4}, bytes.Repeat([]byte{'a'}, 540)...),
		{1, 0, 22, 1, 1, 1, 1, 'a', '.', 0},
		{1, 0, 22, 1, 1, 1, 1, 'a', 'a', 0},
		{1, 0, 22, 1, 1, 1, 1, 0},
		{1, 0, 22, 0, 0, 0, 1, 0, 'a', 'b', 'c'},
	}
	requestErrors := []error{
		os.ErrDeadlineExceeded,
		ErrUnsuportedCommand,
		io.EOF,
		ErrBadCredentials,
		ErrBadCredentials,
		ErrIPAuthFailed,
		io.ErrUnexpectedEOF,
	}
	errChan := make(chan error)
	for nr, request := range badRequests {
		c1, c2 := net.Pipe()
		req := GetSocks4Request()
		fields := req.Fields
		fields.UserIP = "pipe"
		fields.ProxyIP = "pipe"
		fields.Conn = c1
		fields.ProxyConfig = &authmock.Mock{
			IPAuthRet:          authorizer.BadAuthResult,
			CredentialsAuthRet: authorizer.BadAuthResult,
		}
		fields.Timeouts = &corestructs.Timeouts{Handshake: 1 * time.Second}
		go func(conn net.Conn, data []byte) {
			conn.Write(request)
		}(c2, request)
		go func(req *Socks4Request) {
			errChan <- req.Read()
		}(req)
		err := <-errChan
		if err == nil {
			t.Errorf("Test #%d: Expected err to not be nil, got nil", nr+1)
		} else if !errors.Is(err, requestErrors[nr]) {
			t.Errorf("Test #%d: Expected err to be %s, got %s", nr+1, requestErrors[nr], err)
		}
		c1.Close()
		c2.Close()
		PutSocks4Request(req)
	}
}
