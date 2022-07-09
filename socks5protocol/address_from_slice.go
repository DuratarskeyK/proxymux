package socks5protocol

func AddressFromSlice(buf []byte) (*Address, int, error) {
	bufLen := len(buf)
	if bufLen < 1 {
		return nil, 0, ErrSliceTooShort
	}
	res := &Address{
		Type: buf[0],
	}
	var portStart, addrLen int
	switch res.Type {
	case IPv4Address:
		if bufLen < 7 {
			return nil, 0, ErrSliceTooShort
		}
		res.Value = make([]byte, 4)
		copy(res.Value, buf[1:5])
		portStart = 5
		addrLen = 7
	case IPv6Address:
		if bufLen < 19 {
			return nil, 0, ErrSliceTooShort
		}
		res.Value = make([]byte, 16)
		copy(res.Value, buf[1:17])
		portStart = 17
		addrLen = 19
	case HostnameAddress:
		if bufLen < 2 {
			return nil, 0, ErrSliceTooShort
		}
		sz := int(buf[1])
		if bufLen < 4+sz {
			return nil, 0, ErrSliceTooShort
		}
		res.Value = make([]byte, sz)
		copy(res.Value, buf[2:2+sz])
		portStart = 2 + sz
		addrLen = 4 + sz
	default:
		return nil, 0, ErrUnknownAddressType
	}

	res.Port = (uint16(buf[portStart]) << 8) | uint16(buf[portStart+1])
	res.fillValues()

	return res, addrLen, nil
}
