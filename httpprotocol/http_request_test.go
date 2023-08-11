package httpprotocol

import (
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/duratarskeyk/go-common-utils/authorizer"
	"github.com/duratarskeyk/proxymux/corestructs"
	"github.com/duratarskeyk/proxymux/internal/authmock"
)

type goodTestCase struct {
	authMock    *authmock.Mock
	httpRequest []byte
	firstByte   byte

	host        string
	port        string
	packageID   int
	userID      int
	systemUser  bool
	backconnect bool
	tunnel      bool
}

func TestGoodRequests(t *testing.T) {
	// test http GET credentials auth
	// test http GET ip auth
	// test https GET
	// test CONNECT tunnel
	// test backconnect CONNECT
	testCases := []*goodTestCase{
		{
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 1,
					UserID:    11,
				},
			},
			[]byte("ET http://www.example.org HTTP/1.1\r\nHost: www.example.org\r\nProxy-Authorization: Basic YTpi\r\nX-Header: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n\r\n"),
			'G',
			"www.example.org",
			"80",
			1,
			11,
			false,
			false,
			false,
		},
		{
			&authmock.Mock{
				IPAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 2,
					UserID:    22,
				},
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET http://www.google.com/search?q=123 HTTP/1.1\r\nHost: www.google.com\r\n\r\n"),
			'G',
			"www.google.com",
			"80",
			2,
			22,
			false,
			false,
			false,
		},
		{
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 3,
					UserID:    33,
				},
			},
			[]byte("ET https://www.google.com/search?q=123 HTTP/1.1\r\nHost: www.google.com\r\nProxy-Authorization: Basic YTpi\r\nProxy-Test: test\r\n\r\n"),
			'G',
			"www.google.com",
			"443",
			3,
			33,
			false,
			false,
			false,
		},
		{
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:        true,
					PackageID: 4,
					UserID:    44,
				},
			},
			[]byte("ONNECT example.org:7777 HTTP/1.1\r\nHost: example.org:7777\r\nProxy-Authorization: Basic YTpi\r\n\r\n"),
			'C',
			"example.org",
			"7777",
			4,
			44,
			false,
			false,
			true,
		},
		{
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:          true,
					PackageID:   5,
					UserID:      55,
					Backconnect: true,
				},
			},
			[]byte("ONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nProxy-Authorization: Basic YTpi\r\nX-Clientip: 5.5.5.5\r\nX-Packageid: 5\r\nX-Userid: 55\r\n\r\n"),
			'C',
			"example.org",
			"443",
			5,
			55,
			false,
			true,
			true,
		},
		{
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:          true,
					PackageID:   5,
					UserID:      55,
					Backconnect: true,
				},
			},
			[]byte("ET http://example.org HTTP/1.1\r\nHost: example.org\r\nProxy-Authorization: Basic YTpi\r\nX-Clientip: 5.5.5.5\r\nX-Packageid: 5\r\nX-Userid: 55\r\n\r\n"),
			'G',
			"example.org",
			"80",
			5,
			55,
			false,
			true,
			false,
		},
		{
			&authmock.Mock{
				IPAuthRet: authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.AuthResult{
					OK:         true,
					SystemUser: true,
				},
			},
			[]byte("ONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nProxy-Authorization: Basic YTpi\r\nX-Clientip: 5.5.5.5\r\nX-Packageid: 5\r\nX-Userid: 55\r\n\r\n"),
			'C',
			"example.org",
			"443",
			0,
			0,
			true,
			false,
			true,
		},
	}
	doneCh := make(chan struct{})
	for nr, testCase := range testCases {
		c1, c2 := net.Pipe()
		req := GetHTTPRequest()
		req.FirstByte = testCase.firstByte
		fields := req.Fields
		fields.UserIP = "4.3.2.1"
		fields.ProxyIP = "1.2.3.4"
		fields.PackageID = 0
		fields.UserID = 0
		fields.Conn = c1
		fields.ProxyConfig = testCase.authMock
		fields.Timeouts = &corestructs.Timeouts{Handshake: 30 * time.Second}
		go func() {
			req.Read()
			doneCh <- struct{}{}
		}()
		c2.Write(testCase.httpRequest)
		<-doneCh
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
		if req.Tunnel != testCase.tunnel {
			t.Errorf("Test #%d: Tunnel must be %v, got %v", nr+1, testCase.tunnel, req.Tunnel)
		}
		if req.Tunnel && req.Request != nil {
			t.Errorf("Test #%d: Request must be nil when Tunnel is set", nr+1)
		} else if !req.Tunnel && req.Request == nil {
			t.Errorf("Test #%d: Request must not be nil when Tunnel is not set", nr+1)
		}
		if !req.Tunnel {
			for header := range req.Request.Header {
				if strings.HasPrefix(header, "Proxy-") {
					t.Errorf("Test #%d: Found header starting with Proxy- in the read request: %s", nr+1, header)
				}
			}
		}
		PutHTTPRequest(req)
		c1.Close()
		c2.Close()
	}
}

type badTestCase struct {
	authMock    *authmock.Mock
	httpRequest []byte
	firstByte   byte

	err error
}

func TestBadRequests(t *testing.T) {
	testCases := []*badTestCase{
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("\x00\x11 \xff\xff \x12\x13\r\n\r\n"),
			'a',
			ErrRequestReadFailed,
		},
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET / HTTP/1.1\r\nHost: example.org\r\n\r\n"),
			'G',
			ErrNotAuthorativeRequest,
		},
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET http://example.org:77777 HTTP/1.1\r\nHost: example.org:77777\r\n\r\n"),
			'G',
			ErrBadPort,
		},
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET http://example.org:77 HTTP/1.1\r\nHost: example.org:77\r\nProxy-Authorization: Bearer abcd\r\n\r\n"),
			'G',
			ErrNotBasicAuth,
		},
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET http://example.org:77 HTTP/1.1\r\nHost: example.org:77\r\nProxy-Authorization: Basic aaaaa\r\n\r\n"),
			'G',
			base64.CorruptInputError(4),
		},
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET http://example.org:77 HTTP/1.1\r\nHost: example.org:77\r\nProxy-Authorization: Basic YWFh\r\n\r\n"),
			'G',
			ErrBadCredentials,
		},
		{
			&authmock.Mock{
				IPAuthRet:          authorizer.BadAuthResult,
				CredentialsAuthRet: authorizer.BadAuthResult,
			},
			[]byte("ET http://example.org:77 HTTP/1.1\r\nHost: example.org:77\r\n\r\n"),
			'G',
			ErrIPAuthFailed,
		},
	}
	errCh := make(chan error)
	for nr, testCase := range testCases {
		c1, c2 := net.Pipe()
		req := GetHTTPRequest()
		req.FirstByte = testCase.firstByte
		fields := req.Fields
		fields.UserIP = "4.3.2.1"
		fields.ProxyIP = "1.2.3.4"
		fields.PackageID = 0
		fields.UserID = 0
		fields.Conn = c1
		fields.ProxyConfig = testCase.authMock
		fields.Timeouts = &corestructs.Timeouts{Handshake: 30 * time.Second}
		go func() {
			errCh <- req.Read()
		}()
		c2.Write(testCase.httpRequest)
		err := <-errCh
		if !errors.Is(err, testCase.err) {
			t.Errorf("Test #%d: Expected %s, got %s", nr+1, testCase.err, errors.Unwrap(err))
		}
	}
}
