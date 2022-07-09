package socks5protocol

const socks5Version = byte(5)

// Auth constants
const (
	noAuthID = byte(0)

	userPassAuthID  = byte(2)
	userAuthVersion = byte(1)

	noAcceptableID = byte(255)

	authSuccessStatus = byte(0)
	authFailureStatus = byte(1)
)

// Command types
const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
)

// Address types
const (
	IPv4Address     = uint8(1)
	HostnameAddress = uint8(3)
	IPv6Address     = uint8(4)
)

// Auth responses
var (
	noAuth = []byte{socks5Version, noAuthID}

	userPassAuth = []byte{socks5Version, userPassAuthID}
	authSuccess  = []byte{userAuthVersion, authSuccessStatus}
	authFailure  = []byte{userAuthVersion, authFailureStatus}

	noAcceptable = []byte{socks5Version, noAcceptableID}
)

// Reply codes
const (
	SuccessReply byte = iota
	ServerFailure
	RuleFailure
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddrTypeNotSupported
)
