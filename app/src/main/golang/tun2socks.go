//go:build linux || android

package vlinkjni

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// configureUpstreamSocks parses h.config.UpstreamSocks and configures the tunnel
// with a proxy, socket options and direct dialers suitable for upstream mode.
func configureUpstreamSocks(h *TunInboundHandler) error {
	if h == nil || h.config == nil {
		return fmt.Errorf("nil handler or config")
	}
	socksServerAddr := h.config.UpstreamSocks
	if socksServerAddr == "" {
		return fmt.Errorf("empty upstream socks")
	}
	if !strings.Contains(socksServerAddr, "://") {
		socksServerAddr = "socks5://" + socksServerAddr
	}
	uParsed, err := url.Parse(socksServerAddr)
	if err != nil {
		return fmt.Errorf("invalid upstream socks %s: %v", socksServerAddr, err)
	}
	addr := uParsed.Host
	user := ""
	pass := ""
	if uParsed.User != nil {
		user = uParsed.User.Username()
		pass, _ = uParsed.User.Password()
	}
	upProxy, err := newSocks5Proxy(addr, user, pass)
	if err != nil {
		return fmt.Errorf("failed to create upstream proxy: %v", err)
	}
	// upProxy provides DialTCP and DialUDP behaviors; store it on tunnel for use.
	T().setProxy(upProxy)

	// register protect_fd socket option on local dialer registry
	RegisterSockOpt(func(_, _ string, rc syscall.RawConn) error {
		var innerErr error
		if err := rc.Control(func(fd uintptr) {
			if !protectFD(int(fd)) {
				innerErr = fmt.Errorf("TUN protect_fd failed for fd %d", fd)
				return
			}
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return innerErr
	})

	// Configure direct dialers on tunnel for LAN/direct logic
	T().setDirectDialer(func(ctx context.Context, m *Metadata) (net.Conn, error) {
		// dial directly to destination using unified dialWithProtect
		return dialWithProtect(ctx, "tcp", m.DestinationAddress(), 3*time.Second)
	})
	T().setDirectPacketDialer(func(m *Metadata) (net.PacketConn, error) {
		// create a UDP packet conn for direct UDP
		return dialPacketWithProtect("udp", "")
	})
	return nil
}

// routeTun2SocksUpstreamTCP handles TCP connections in tun2socksUpstream mode by
// delegating to the tunnel manager which will use the configured upstream proxy or direct dialer.
func (h *TunInboundHandler) routeTun2SocksUpstreamTCP(wrapped *adapterTCPConn) {
	log.Printf("tun2socks upstream: handling TCP ID=%v", wrapped.ID())
	T().handleTCP(wrapped)
}

// routeTun2SocksUpstreamUDP handles UDP connections in tun2socksUpstream mode by
// delegating to the tunnel manager which will use the configured upstream proxy or direct packet dialer.
func (h *TunInboundHandler) routeTun2SocksUpstreamUDP(wrapped *adapterUDPConn) {
	log.Printf("tun2socks upstream: handling UDP ID=%v", wrapped.ID())
	T().handleUDP(wrapped)
}
