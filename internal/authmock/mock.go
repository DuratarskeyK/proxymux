package authmock

import "github.com/duratarskeyk/go-common-utils/authorizer"

type Mock struct {
	IPAuthRet          authorizer.AuthResult
	CredentialsAuthRet authorizer.AuthResult
}

func (m *Mock) IPAuth(proxyIP, userIP string) authorizer.AuthResult {
	return m.IPAuthRet
}

func (m *Mock) CredentialsAuth(proxyIP, username, password string) authorizer.AuthResult {
	return m.CredentialsAuthRet
}
