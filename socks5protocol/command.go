package socks5protocol

func readCommand(req *Socks5Request) error {
	header := []byte{0, 0, 0, 0}
	var err error
	if _, err = req.handshakeConn.Read(header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return ErrVersionMismatch
	}
	if header[1] < ConnectCommand || header[1] > AssociateCommand {
		return ErrUnkownCommand
	}
	req.Command = header[1]
	err = readAddress(req, header[3])
	if err != nil {
		return err
	}

	return nil
}
