package protocol

import (
	tlsclient "github.com/bogdanfinn/tls-client"
)

// newJar 创建一个 tls-client 官方兼容的 RFC 6265 CookieJar。
func newJar() tlsclient.CookieJar {
	return tlsclient.NewCookieJar()
}
