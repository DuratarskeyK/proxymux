package httpprotocol

import (
	"fmt"
	"net"
	"time"
)

var HTTP400BadRequest = "HTTP/1.1 400 Bad Request\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: BAD_REQUEST\r\n" +
	"Connection: close\r\n%s"

var HTTP407Unauthorized = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	`Proxy-Authenticate: Basic realm="Proxy"` + "\r\n" +
	"Connection: close\r\n%s"

var HTTP451Forbidden = "HTTP/1.1 451 Unavailable For Legal Reasons\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: TARGET_HOST_IS_BLOCKED\r\n" +
	"Connection: close\r\n%s"

var HTTP570ResolutionError = "HTTP/1.1 570 DNS Resolution Failed\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: TARGET_HOST_DNS_RESOLUTION_FAILED\r\n" +
	"Connection: close\r\n%s"

var HTTP571IPv6NotSupported = "HTTP/1.1 571 IPv6 Not Supported\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: IPV6_NOT_SUPPORTED\r\n" +
	"Connection: close\r\n%s"

var HTTP572TargetConnectionError = "HTTP/1.1 572 Target Host Connection Failed\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: TARGET_HOST_CONNECTION_FAILED\r\n" +
	"Connection: close\r\n%s"

var HTTP573CommunicationError = "HTTP/1.1 573 Target Host Communication Error\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: TARGET_HOST_COMMUNICATION_FAILED\r\n" +
	"Connection: close\r\n%s"

var HTTP529ProxyRatelimitReached = "HTTP/1.1 529 Proxy Ratelimit Reached\r\n" +
	"Server: FaaS v1.3-20220203-7fa38bd5af\r\n" +
	"Date: %s\r\n" +
	"%s" +
	"X-Request-Error: PROXY_RATELIMIT_REACHED\r\n" +
	"Connection: close\r\n%s"

const contentTypeHeader = "Content-Type: text/plain; charset=utf-8\r\n"

func WriteHTTPError(conn net.Conn, errStr, body string) {
	now := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	if len(body) == 0 {
		fmt.Fprintf(conn, errStr, now, "", "\r\n")
		return
	}
	contentHeaders := fmt.Sprintf("%sContent-Length: %d\r\n", contentTypeHeader, len(body))
	fmt.Fprintf(conn, errStr, now, contentHeaders, "\r\n"+body)
}
