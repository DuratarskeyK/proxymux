package socks4protocol

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/duratarskeyk/go-common-utils/authorizer"
	"github.com/duratarskeyk/go-common-utils/idlenet"
	"github.com/duratarskeyk/proxymux/corestructs"
	"go.uber.org/zap"
)

type Socks4Request struct {
	Fields *corestructs.Fields

	connWrapper   reader
	limitedReader io.LimitedReader
	buffer        *bufio.Reader
}

// 512 - 8 + 12 = 516, 8 bytes already read when we need to read ident and possibly a domain name
// and package/user id and client ip for backconnect
const requestSizeLimit = 516

func (req *Socks4Request) Read() error {
	fields := req.Fields
	fields.LogFields = append(fields.LogFields,
		zap.String("user_ip", fields.UserIP),
		zap.String("proxy_ip", fields.ProxyIP),
	)
	reqBytes := make([]byte, 7)
	if _, err := idlenet.ReadWithTimeout(fields.Conn, fields.Timeouts.Handshake, reqBytes); err != nil {
		return &ErrBadRequest{err: err}
	}
	if reqBytes[0] != 1 {
		return &ErrBadRequest{err: ErrUnsuportedCommand}
	}
	fields.PortNum = uint16(reqBytes[1])<<8 | uint16(reqBytes[2])
	fields.Port = strconv.Itoa(int(fields.PortNum))
	socks4a := false
	ip := reqBytes[3:7]
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
		socks4a = true
		fields.LogFields = append(fields.LogFields, zap.String("type", "SOCKS4a"))
	} else {
		fields.HostIP = net.IP(ip)
		fields.Host = fields.HostIP.String()
		fields.HostType = corestructs.HostTypeIPv4
		fields.LogFields = append(fields.LogFields, zap.String("type", "SOCKS4"))
	}
	req.connWrapper.conn = fields.Conn
	req.connWrapper.total = 0
	req.connWrapper.readTimeout = fields.Timeouts.Handshake
	req.limitedReader.R = &req.connWrapper
	req.limitedReader.N = requestSizeLimit
	if req.buffer == nil {
		req.buffer = bufio.NewReaderSize(&req.limitedReader, 128)
	} else {
		req.buffer.Reset(&req.limitedReader)
	}

	var (
		err    error
		identd string
	)
	identd, err = req.buffer.ReadString(0)
	if err != nil {
		return &ErrBadRequest{err: err}
	}
	identd = identd[:len(identd)-1]
	if socks4a {
		fields.Host, err = req.buffer.ReadString(0)
		if err != nil {
			return &ErrBadRequest{err: err}
		}
		fields.Host = fields.Host[:len(fields.Host)-1]
		fields.HostType = corestructs.HostTypeHostname
	}

	fields.Login = ""
	fields.Password = ""
	var result authorizer.AuthResult
	auth := fields.ProxyConfig.(authorizer.Authorizer)
	if result = auth.IPAuth(fields.ProxyIP, fields.UserIP); result.OK {
		fields.PackageID = result.PackageID
		fields.UserID = result.UserID
		fields.Backconnect = false
		fields.SystemUser = false
	} else if identd != "" {
		pos := strings.IndexByte(identd, '.')
		if pos == -1 {
			fields.Login = identd
			result = auth.CredentialsAuth(fields.ProxyIP, identd, "")
		} else {
			fields.Login = identd[:pos]
			fields.Password = identd[pos+1:]
			result = auth.CredentialsAuth(fields.ProxyIP, fields.Login, fields.Password)
		}
		if !result.OK {
			return &ErrAuthorization{err: ErrBadCredentials}
		}
		fields.PackageID = result.PackageID
		fields.UserID = result.UserID
		fields.SystemUser = result.SystemUser
		fields.Backconnect = result.Backconnect
		if fields.Backconnect {
			backconnectData := make([]byte, 12)
			if _, err := req.buffer.Read(backconnectData); err != nil {
				return &ErrBadRequest{err: err}
			}
			packageID := uint(backconnectData[0])<<24 | uint(backconnectData[1])<<16 | uint(backconnectData[2])<<8 | uint(backconnectData[3])
			userID := uint(backconnectData[4])<<24 | uint(backconnectData[5])<<16 | uint(backconnectData[6])<<8 | uint(backconnectData[7])
			fields.PackageID = int(packageID)
			fields.UserID = int(userID)
			fields.UserIP = fmt.Sprintf("%d.%d.%d.%d", backconnectData[8], backconnectData[9], backconnectData[10], backconnectData[11])
			fields.LogFields[0].String = fields.UserIP
		}
	} else {
		return &ErrAuthorization{err: ErrIPAuthFailed}
	}

	fields.FillLogFields()

	proxyIPOctets := []byte(net.ParseIP(fields.ProxyIP).To4())
	fields.ProxyIPNum = (uint32(proxyIPOctets[0]) << 24) | (uint32(proxyIPOctets[1]) << 16) |
		(uint32(proxyIPOctets[2]) << 8) | uint32(proxyIPOctets[3])

	fields.Upload = req.connWrapper.total + 8

	return nil
}
