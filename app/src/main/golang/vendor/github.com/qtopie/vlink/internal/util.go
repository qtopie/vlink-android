package internal

import (
	"net/url"
)

// ParseURL parses a Shadowsocks URL of the form ss://cipher:password@host:port
func ParseURL(s string) (addr, cipher, password string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		cipher = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
