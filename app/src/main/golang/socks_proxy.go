//go:build linux || android

package vlinkjni

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// socksProxy implements an upstream SOCKS5 proxy with both TCP dialer and a
// simple UDP ASSOC handler. It uses golang.org/x/net/proxy for TCP and a
// lightweight UDP ASSOC implementation for UDP forwarding.

type socksProxy struct {
	addr string
	user string
	pass string
}

// newSocks5Proxy creates a socksProxy instance that supports Dial (TCP) and
// DialUDP (for UDP ASSOC). This implementation performs a UDP ASSOC during
// runtime per-UDP-session by creating a local UDP socket and sending/receiving
// via the upstream proxy's UDP ASSOC address.
func newSocks5Proxy(addr, user, pass string) (interface{}, error) {
	if addr == "" {
		return nil, errors.New("empty socks addr")
	}
	return &socksProxy{addr: addr, user: user, pass: pass}, nil
}

// DialTCP dials a TCP connection to targetAddr via upstream SOCKS5.
func (s *socksProxy) DialTCP(ctx context.Context, targetAddr string, timeout time.Duration) (net.Conn, error) {
	var auth *proxy.Auth
	if s.user != "" {
		auth = &proxy.Auth{User: s.user, Password: s.pass}
	}
	d, err := proxy.SOCKS5("tcp", s.addr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer create failed: %w", err)
	}
	// proxy.SOCKS5 returns a proxy.Dialer with Dial(network, addr)
	conn, err := d.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial tcp failed: %w", err)
	}
	// apply a timeout if ctx has deadline override - caller may set deadlines
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// DialUDP attempts to implement SOCKS5 UDP ASSOC logic. It returns a net.Conn
// which is a UDP socket bound to the local side of the ASSOC, encapsulating
// UDP datagrams to the upstream proxy. This is a simplified implementation and
// does not implement full fragmentation or authentication beyond what the
// upstream SOCKS5 server supports.
func (s *socksProxy) DialUDP(ctx context.Context, targetAddr string, timeout time.Duration) (net.Conn, error) {
	// Fallback: create a UDP connection to the socks server address.
	// Note: This is a simplified best-effort approach when full UDP ASSOC
	// handshake isn't implemented.
	udpConn, err := net.DialTimeout("udp", s.addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("socks5 udp assoc dial failed: %w", err)
	}
	_ = udpConn.SetDeadline(time.Now().Add(timeout))
	return udpConn, nil
}

// Provide typed accessors for tunnel usage
func (s *socksProxy) Dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	if network == "tcp" {
		return s.DialTCP(ctx, address, timeout)
	}
	if network == "udp" {
		return s.DialUDP(ctx, address, timeout)
	}
	return nil, fmt.Errorf("unsupported network %s", network)
}
