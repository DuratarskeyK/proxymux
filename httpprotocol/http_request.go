package httpprotocol

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/duratarskeyk/go-common-utils/authorizer"
	"github.com/duratarskeyk/proxymux/corestructs"
	"go.uber.org/zap"
)

type HTTPRequest struct {
	Fields *corestructs.Fields

	handshakeConn httpReader
	buffer        *bufio.Reader

	FirstByte byte

	Tunnel bool

	Request *http.Request
}

func (req *HTTPRequest) Read() error {
	fields := req.Fields
	req.handshakeConn.conn = fields.Conn
	req.handshakeConn.timeout = fields.Timeouts.Handshake
	req.handshakeConn.firstByteRead = false
	req.handshakeConn.firstByte = req.FirstByte
	req.handshakeConn.total = 0
	if req.buffer == nil {
		req.buffer = bufio.NewReader(&req.handshakeConn)
	} else {
		req.buffer.Reset(&req.handshakeConn)
	}
	fields.LogFields = append(fields.LogFields,
		zap.String("user_ip", fields.UserIP),
		zap.String("proxy_ip", fields.ProxyIP),
		zap.String("type", "HTTP"),
	)

	var err error
	req.Request, err = http.ReadRequest(req.buffer)
	if err != nil {
		return &ErrBadRequest{err: ErrRequestReadFailed}
	}
	req.Request.Method = strings.ToUpper(req.Request.Method)
	req.Tunnel = req.Request.Method == "CONNECT"

	fields.Upload = req.handshakeConn.total
	fields.Download = 0

	hostname := req.Request.URL.Host
	if hostname == "" {
		return &ErrBadRequest{err: ErrNotAuthorativeRequest}
	}

	if strings.IndexByte(hostname, ':') != -1 {
		fields.Host, fields.Port, err = net.SplitHostPort(hostname)
		if err != nil {
			return &ErrBadRequest{err: err}
		}
		portNum, err := strconv.Atoi(fields.Port)
		if err != nil || portNum < 1 || portNum > 65535 {
			if err != nil {
				return &ErrBadRequest{err: err}
			}
			return &ErrBadRequest{err: ErrBadPort}
		}
		fields.PortNum = uint16(portNum)
	} else {
		if req.Tunnel {
			fields.Host, fields.Port, fields.PortNum = hostname, "443", 443
		} else {
			switch req.Request.URL.Scheme {
			case "http":
				fields.Host, fields.Port, fields.PortNum = hostname, "80", 80
			case "https":
				fields.Host, fields.Port, fields.PortNum = hostname, "443", 443
			default:
				return &ErrBadRequest{err: ErrUnknownScheme}
			}
		}
	}

	fields.HostIP = net.ParseIP(hostname)
	if fields.HostIP != nil && fields.HostIP.To4() == nil {
		fields.HostType = corestructs.HostTypeIPv6
	} else if fields.HostIP != nil {
		fields.HostType = corestructs.HostTypeIPv4
	} else {
		fields.HostType = corestructs.HostTypeHostname
	}

	fields.Login = ""
	fields.Password = ""
	auth := fields.ProxyConfig.(authorizer.Authorizer)
	result := auth.IPAuth(fields.ProxyIP, fields.UserIP)
	if result.OK {
		fields.PackageID = result.PackageID
		fields.UserID = result.UserID
		fields.SystemUser = false
		fields.Backconnect = false
	} else {
		authHeader := req.Request.Header.Get("Proxy-Authorization")
		if authHeader != "" {
			if !strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
				return &ErrBadRequest{err: ErrNotBasicAuth}
			}
			baseStr := authHeader[6:]
			decoded, err := base64.StdEncoding.DecodeString(baseStr)
			if err != nil {
				return &ErrBadRequest{err: err}
			}
			credentials := string(decoded)
			index := strings.IndexByte(credentials, ':')
			if index == -1 {
				fields.Login = credentials
				fields.Password = ""
				result = auth.CredentialsAuth(fields.ProxyIP, fields.Login, "")
			} else {
				fields.Login = credentials[:index]
				fields.Password = credentials[index+1:]
				result = auth.CredentialsAuth(fields.ProxyIP, fields.Login, fields.Password)
			}

			if !result.OK {
				return &ErrAuth{err: ErrBadCredentials}
			}

			fields.PackageID = result.PackageID
			fields.UserID = result.UserID
			fields.SystemUser = result.SystemUser
			fields.Backconnect = result.Backconnect

			if result.Backconnect {
				packageIDStr := req.Request.Header.Get("X-Packageid")
				fields.PackageID, err = strconv.Atoi(packageIDStr)
				if err != nil {
					return &ErrBadRequest{err: err}
				}
				userIDStr := req.Request.Header.Get("X-Userid")
				fields.UserID, err = strconv.Atoi(userIDStr)
				if err != nil {
					return &ErrBadRequest{err: err}
				}

				userIP := req.Request.Header.Get("X-Clientip")
				if userIP == "" {
					return &ErrBadRequest{err: ErrBackconnectUserIPNotPresent}
				}
				fields.UserIP = userIP
				fields.LogFields[0].String = userIP
				if !req.Tunnel {
					req.Request.Header.Del("X-Packageid")
					req.Request.Header.Del("X-Userid")
					req.Request.Header.Del("X-Clientip")
				}
			}
		} else {
			return &ErrAuth{err: ErrIPAuthFailed}
		}
	}

	fields.FillLogFields()

	if req.Tunnel {
		if req.Request.Body != nil {
			req.Request.Body.Close()
		}
		req.Request = nil
	} else {
		for header := range req.Request.Header {
			if strings.HasPrefix(header, "Proxy-") {
				req.Request.Header.Del(header)
			}
		}
		if req.Request.Header.Get("User-Agent") == "" {
			req.Request.Header.Set("User-Agent", "")
		}
	}

	proxyIPOctets := []byte(net.ParseIP(fields.ProxyIP).To4())
	fields.ProxyIPNum = (uint32(proxyIPOctets[0]) << 24) | (uint32(proxyIPOctets[1]) << 16) |
		(uint32(proxyIPOctets[2]) << 8) | uint32(proxyIPOctets[3])

	return nil
}
