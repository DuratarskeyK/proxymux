package corestructs

import (
	"net"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestClean(t *testing.T) {
	fields := &Fields{
		Conn:        &net.TCPConn{},
		ProxyConfig: &struct{}{},
		DialerTCP:   &net.Dialer{},
		DialerUDP:   &net.Dialer{},
		Timeouts:    &Timeouts{},
		HostIP:      net.IPv4(1, 2, 3, 4),
		LogFields: []zapcore.Field{
			zap.String("a", "b"),
			zap.String("c", "d"),
			zap.String("ew", "ww"),
		},
	}
	fields.Clean()
	if fields.Conn != nil || fields.ProxyConfig != nil || fields.DialerTCP != nil || fields.Timeouts != nil || fields.HostIP != nil || len(fields.LogFields) != 0 {
		t.Error("Clean failed")
	}
}

func TestFillLogFields(t *testing.T) {
	testFields := []*Fields{
		{
			SystemUser: true,
			Host:       "1.2.3.4",
			PortNum:    777,
			LogFields:  []zap.Field{},
		},
		{
			SystemUser:  false,
			Backconnect: false,
			PackageID:   1,
			UserID:      11,
			Host:        "ya.ru",
			PortNum:     80,
			LogFields:   []zap.Field{},
		},
		{
			SystemUser:  false,
			Backconnect: true,
			PackageID:   2,
			UserID:      22,
			Host:        "example.org",
			PortNum:     443,
			LogFields:   []zap.Field{},
		},
	}
	testResults := [][]zapcore.Field{
		{
			zap.Bool("system_user", true),
			zap.String("package_type", "proxy"),
			zap.String("host", "1.2.3.4"),
			zap.Uint16("port", 777),
		},
		{
			zap.Int("package_id", 1),
			zap.Int("user_id", 11),
			zap.String("package_type", "proxy"),
			zap.String("host", "ya.ru"),
			zap.Uint16("port", 80),
		},
		{
			zap.Int("package_id", 2),
			zap.Int("user_id", 22),
			zap.String("package_type", "backconnect"),
			zap.String("host", "example.org"),
			zap.Uint16("port", 443),
		},
	}
	for i, v := range testFields {
		v.FillLogFields()
		if len(v.LogFields) != len(testResults[i]) {
			t.Errorf("Test %d: Lens don't match %d != %d", i+1, len(v.LogFields), len(testResults[i]))
			continue
		}
		for nr := range testFields[i].LogFields {
			if testFields[i].LogFields[nr] != testResults[i][nr] {
				t.Errorf("Test %d: Field %d doesn't match: %v != %v", i+1, nr+1, testFields[i].LogFields[nr], testResults[i][nr])
			}
		}
	}
}
