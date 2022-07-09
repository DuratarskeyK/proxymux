package corestructs

import (
	"net"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	HostTypeIPv4 = iota
	HostTypeIPv6
	HostTypeHostname
)

type Fields struct {
	Conn        net.Conn
	ProxyConfig interface{}
	Timeouts    *Timeouts

	DialerTCP *net.Dialer
	DialerUDP *net.Dialer

	UserIP string

	ProxyIP    string
	ProxyIPNum uint32

	Login       string
	Password    string
	PackageID   int
	UserID      int
	Backconnect bool
	SystemUser  bool

	HostType int
	Host     string
	HostIP   net.IP
	Port     string
	PortNum  uint16

	Download int64
	Upload   int64

	LogFields []zapcore.Field
}

func (f *Fields) Clean() {
	f.Conn = nil
	f.ProxyConfig = nil
	f.DialerTCP = nil
	f.DialerUDP = nil
	f.Timeouts = nil
	f.HostIP = nil
	f.LogFields = f.LogFields[:0]
}

func (f *Fields) FillLogFields() {
	if f.SystemUser {
		f.LogFields = append(f.LogFields, zap.Bool("system_user", true), zap.String("package_type", "proxy"))
	} else {
		f.LogFields = append(f.LogFields,
			zap.Int("package_id", f.PackageID),
			zap.Int("user_id", f.UserID),
		)
		if f.Backconnect {
			f.LogFields = append(f.LogFields, zap.String("package_type", "backconnect"))
		} else {
			f.LogFields = append(f.LogFields, zap.String("package_type", "proxy"))
		}
	}

	f.LogFields = append(f.LogFields,
		zap.String("host", f.Host),
		zap.Uint16("port", f.PortNum),
	)
}
