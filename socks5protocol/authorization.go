package socks5protocol

import "github.com/duratarskeyk/go-common-utils/authorizer"

func authorize(req *Socks5Request) error {
	fields := req.Fields
	proxyIP := fields.ProxyIP

	var err error

	header := []byte{0, 0}
	if _, err = req.handshakeConn.Read(header[:1]); err != nil {
		return err
	}

	if header[0] == 0 {
		return ErrNoAuthMethodsOffered
	}

	methods := make([]byte, header[0])
	if _, err = req.handshakeConn.Read(methods); err != nil {
		return err
	}

	noAuthMethodPresent := false
	userPassAuthMethodPresent := false
	for _, method := range methods {
		if method == noAuthID {
			noAuthMethodPresent = true
		} else if method == userPassAuthID {
			userPassAuthMethodPresent = true
		}
	}

	fields.Login = ""
	fields.Password = ""
	auth := fields.ProxyConfig.(authorizer.Authorizer)
	result := auth.IPAuth(proxyIP, fields.UserIP)
	doFakeCredentialsAuth := false
	if result.OK {
		fields.PackageID = result.PackageID
		fields.UserID = result.UserID
		fields.SystemUser = false
		fields.Backconnect = false
		if noAuthMethodPresent {
			_, err = req.handshakeConn.Write(noAuth)
			return err
		}
		doFakeCredentialsAuth = true
	}

	if userPassAuthMethodPresent {
		if _, err = req.handshakeConn.Write(userPassAuth); err != nil {
			return err
		}
		if _, err = req.handshakeConn.Read(header); err != nil {
			return err
		}

		if header[0] != userAuthVersion {
			return ErrUserAuthVersionMismatch
		}
		username := make([]byte, header[1]+1)
		if _, err = req.handshakeConn.Read(username); err != nil {
			return err
		}
		password := make([]byte, username[header[1]])
		if _, err = req.handshakeConn.Read(password); err != nil {
			return err
		}
		username = username[:header[1]]

		fields.Login = string(username)
		fields.Password = string(password)

		if !doFakeCredentialsAuth {
			result = auth.CredentialsAuth(proxyIP, fields.Login, fields.Password)
			if !result.OK {
				if _, err = req.handshakeConn.Write(authFailure); err != nil {
					return err
				}
				return ErrBadCredentials
			}
			fields.PackageID = result.PackageID
			fields.UserID = result.UserID
			fields.SystemUser = result.SystemUser
			fields.Backconnect = result.Backconnect
		}

		_, err = req.handshakeConn.Write(authSuccess)
		return err
	}

	if _, err = req.handshakeConn.Write(noAcceptable); err != nil {
		return err
	}

	return ErrNoAcceptableAuthMethod
}
