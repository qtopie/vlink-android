//go:build linux

package inbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/qtopie/vlink/internal"
	"github.com/qtopie/vlink/internal/router"
	"github.com/qtopie/vlink/proxy/ebpf"
	"github.com/qtopie/vlink/socks"
)

type TProxyHandler struct {
	config *InboundConfig
	tcpLn  net.Listener
	udpLn  *net.UDPConn
	closed chan struct{}
	// metrics
	socksDialAttempts uint64
	socksDialSuccess  uint64
	// warm pool of pre-established TCP connections to local SOCKS server
	socksWarmPool chan net.Conn
}

func (h *TProxyHandler) SetConfig(c *InboundConfig) {
	h.config = c
	h.closed = make(chan struct{})
}

func (h *TProxyHandler) Start() error {
	listenAddr := fmt.Sprintf("127.0.0.1:%d", h.config.ListenPort)

	// --- TCP Listener ---
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// IP_TRANSPARENT = 19
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 19, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	ln, err := lc.Listen(context.Background(), "tcp4", listenAddr)
	if err != nil {
		return fmt.Errorf("tcp tproxy listen: %v", err)
	}
	h.tcpLn = ln
	go h.acceptTCP()

	// --- UDP Listener ---
	// For UDP, we also need IP_RECVORIGDSTADDR to know where the packet was going
	udpLc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 19, 1); err != nil { // IP_TRANSPARENT
					opErr = err
					return
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 20, 1); err != nil { // IP_RECVORIGDSTADDR
					opErr = err
					return
				}
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	pktConn, err := udpLc.ListenPacket(context.Background(), "udp4", listenAddr)
	if err != nil {
		ln.Close()
		return fmt.Errorf("udp tproxy listen: %v", err)
	}
	h.udpLn = pktConn.(*net.UDPConn)
	go h.acceptUDP()

	// Initialize warm pool for SocksProxy if configured
	if h.config.SocksProxy != "" {
		if h.config.SocksPoolSize == 0 {
			h.config.SocksPoolSize = DefaultSocksPoolSize
		}
		if h.config.SocksPoolSize > 0 {
			h.socksWarmPool = make(chan net.Conn, h.config.SocksPoolSize)
		// background fill to keep the pool warm
		go func() {
			for i := 0; i < h.config.SocksPoolSize; i++ {
				c, err := h.dialRawSocks()
				if err != nil {
					// if dialing fails, wait and retry
					time.Sleep(time.Second)
					i--
					continue
				}
				select {
				case h.socksWarmPool <- c:
				default:
					c.Close()
				}
			}
		}()
		}
	}

	internal.Debugf("TProxy listening on %s (TCP/UDP)", listenAddr)
	return nil
}

func (h *TProxyHandler) Close() error {
	close(h.closed)
	if h.tcpLn != nil {
		h.tcpLn.Close()
	}
	if h.udpLn != nil {
		h.udpLn.Close()
	}
	// close warm pool and all pooled connections
	if h.socksWarmPool != nil {
		close(h.socksWarmPool)
		for c := range h.socksWarmPool {
			c.Close()
		}
	}
	return nil
}

func (h *TProxyHandler) acceptTCP() {
	for {
		conn, err := h.tcpLn.Accept()
		if err != nil {
			select {
			case <-h.closed:
				return
			default:
				internal.Errorf("TProxy TCP accept error: %v", err)
				time.Sleep(time.Second)
				continue
			}
		}
		internal.Debugf("TProxy: accepted TCP connection from %v", conn.RemoteAddr())
		go h.handleTCP(conn)
	}
}

func (h *TProxyHandler) handleTCP(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	internal.Debugf("TProxy: handleTCP new connection from %v", remote)

	// Get original destination
	origDst, err := ebpf.GetOriginalDst(conn)
	if err != nil {
		internal.Errorf("TProxy: failed to get original destination for %v: %v", remote, err)
		return
	}

	internal.Debugf("TProxy: original destination for %v is %s", remote, origDst)

	// Decision: Proxy or Direct?
	host, _, _ := net.SplitHostPort(origDst)

	// Default shouldProxy is per-inbound DefaultProxy setting.
	shouldProxy := h.config.DefaultProxy
	if h.config.RuleManager != nil {
		// Convert DefaultProxy bool to a fallback action for the rule matcher.
		fallback := router.ActionDirect
		if h.config.DefaultProxy {
			fallback = router.ActionProxy
		}
		action := h.config.RuleManager.MatchWithFallback(host, fallback)
		shouldProxy = (action == router.ActionProxy)
	}

	if shouldProxy {
		internal.Debugf("TProxy: %v -> %s matched proxy rules (proxy=true)", remote, origDst)
		// If a local SocksProxy is configured, forward proxied traffic to it.
		if h.config.SocksProxy != "" {
			internal.Debugf("TProxy: forwarding proxied connection from %v to local SOCKS %s", remote, h.config.SocksProxy)
			// Dial using shared proxy DialSocks5 which applies ebpf control (SO_MARK)
			start := time.Now()
			atomic.AddUint64(&h.socksDialAttempts, 1)
			// Try to use a warm raw TCP connection to the SOCKS server. If none
			// are available, dial immediately. The raw connection will be used to
			// perform a client-side SOCKS CONNECT (see socks.ClientConnect) and
			// is consumed by that handshake; a background refill will replace it.
			var raw net.Conn
			select {
			case raw = <-h.socksWarmPool:
			default:
				raw, err = h.dialRawSocks()
			}
			dialLatency := time.Since(start)
			if err != nil {
				internal.Errorf("TProxy: failed to connect to local SOCKS %s for %v: %v (latency=%s)", h.config.SocksProxy, remote, err, dialLatency)
				return
			}
			// perform client-side socks CONNECT on the raw conn
			if err := socks.ClientConnect(raw, origDst); err != nil {
				raw.Close()
				internal.Errorf("TProxy: socks client connect failed for %v -> %s: %v", remote, origDst, err)
				// replenish background slot
				go h.fillSocksPoolOnce()
				return
			}
			atomic.AddUint64(&h.socksDialSuccess, 1)
			internal.Debugf("TProxy: connected to local SOCKS %s for %v (latency=%s)", h.config.SocksProxy, remote, dialLatency)

			internal.Debugf("TProxy: starting relay between %v and local SOCKS %s", remote, h.config.SocksProxy)
			// Relay data between original connection and the connection to local SOCKS
			go func() {
				_, _ = io.Copy(raw, conn)
				raw.Close()
			}()
			_, _ = io.Copy(conn, raw)
			raw.Close()
			// replenish background slot
			go h.fillSocksPoolOnce()
			return
		}
	} else {
		// Direct connect
		internal.Debugf("TProxy: direct connect for %v to %s", remote, origDst)
		d := net.Dialer{Timeout: 30 * time.Second}
		targetConn, err := d.Dial("tcp", origDst)
		if err != nil {
			internal.Errorf("TProxy: failed to direct dial %s for %v: %v", origDst, remote, err)
			return
		}
		defer targetConn.Close()

		go func() {
			_, err := io.Copy(targetConn, conn)
			if err != nil {
				internal.Errorf("TProxy: direct copy -> target error for %v: %v", remote, err)
			}
		}()
		_, err = io.Copy(conn, targetConn)
		if err != nil {
			internal.Errorf("TProxy: direct copy <- target error for %v: %v", remote, err)
		}
	}
}

func (h *TProxyHandler) acceptUDP() {
	buf := make([]byte, 64*1024)
	oob := make([]byte, 2048)

	for {
		n, oobn, _, addr, err := h.udpLn.ReadMsgUDP(buf, oob)
		if err != nil {
			select {
			case <-h.closed:
				return
			default:
				internal.Errorf("TProxy UDP read error: %v", err)
				time.Sleep(time.Second)
				continue
			}
		}
		// Log packet info
		internal.Debugf("TProxy UDP packet from %v, %d bytes, oob=%d", addr, n, oobn)

		// Get Original Dest
		origDst, err := ebpf.GetOriginalDstUDP(oob[:oobn])
		if err != nil {
			internal.Errorf("TProxy UDP: failed to get original dst for packet from %v: %v", addr, err)
			continue
		}
		internal.Debugf("TProxy UDP: original dst for packet from %v is %s", addr, origDst)

		// Copy data
		payload := make([]byte, n)
		copy(payload, buf[:n])

		go h.handleUDPPacket(payload, addr, origDst)
	}
}

// dialRawSocks dials a raw TCP connection to the configured local SOCKS server
// using ebpf control so the socket is marked and not re-redirected by eBPF.
func (h *TProxyHandler) dialRawSocks() (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, Control: ebpf.GetDialerControl()}
	return d.Dial("tcp", h.config.SocksProxy)
}

// fillSocksPoolOnce attempts to dial a single raw connection and push it into
// the warm pool; used to asynchronously replenish the pool when a slot is
// consumed.
func (h *TProxyHandler) fillSocksPoolOnce() {
	if h.socksWarmPool == nil {
		return
	}
	c, err := h.dialRawSocks()
	if err != nil {
		return
	}
	select {
	case h.socksWarmPool <- c:
	default:
		c.Close()
	}
}

func (h *TProxyHandler) handleUDPPacket(data []byte, clientAddr *net.UDPAddr, origDst string) {
	host, _, _ := net.SplitHostPort(origDst)
	internal.Debugf("TProxy UDP handle packet from %v for %s (len=%d)", clientAddr, origDst, len(data))

	// Default shouldProxy is per-inbound DefaultProxy setting.
	shouldProxy := h.config.DefaultProxy
	if h.config.RuleManager != nil {
		fallback := router.ActionDirect
		if h.config.DefaultProxy {
			fallback = router.ActionProxy
		}
		action := h.config.RuleManager.MatchWithFallback(host, fallback)
		shouldProxy = (action == router.ActionProxy)
	}

	if shouldProxy {
		internal.Debugf("TProxy UDP: proxy required for %s (not implemented) — dropping or TODO implement proxying", origDst)
		// UDP Proxy via V2Ray/Shadowsocks not implemented in this prototype.
		return
	} else {
		// Direct UDP
		internal.Debugf("TProxy UDP: direct send for %s", origDst)
		targetAddr, err := net.ResolveUDPAddr("udp", origDst)
		if err != nil {
			internal.Errorf("TProxy UDP: resolve target %s failed: %v", origDst, err)
			return
		}

		conn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			internal.Errorf("TProxy UDP: dialUDP to %s failed: %v", origDst, err)
			return
		}
		defer conn.Close()

		// Write request
		if _, err := conn.Write(data); err != nil {
			internal.Errorf("TProxy UDP: write to %s failed: %v", origDst, err)
			return
		}

		// Read reply (with timeout)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		respBuf := make([]byte, 4096)
		n, _, err := conn.ReadFromUDP(respBuf)
		if err != nil {
			internal.Errorf("TProxy UDP: read reply from %s failed: %v", origDst, err)
			return
		}

		// Send reply to Client Spoofing Source
		replyConn, err := dialUDPTransparent(clientAddr, targetAddr)
		if err != nil {
			internal.Errorf("TProxy UDP: Failed to create reply conn: %v", err)
			return
		}
		defer replyConn.Close()

		// Use WriteToUDP because dialUDPTransparent returns an unconnected socket bound to localAddr
		if _, err := replyConn.WriteToUDP(respBuf[:n], clientAddr); err != nil {
			internal.Errorf("TProxy UDP: write back to client %v failed: %v", clientAddr, err)
		}
	}
}

func dialUDPTransparent(remoteAddr, localAddr *net.UDPAddr) (*net.UDPConn, error) {
	// We want to send TO remoteAddr (Client) FROM localAddr (Original Dst)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 19, 1) // IP_TRANSPARENT
				if opErr != nil {
					return
				}
				// Allow reuse addr just in case
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	// Bind to the "Original Destination" IP
	conn, err := lc.ListenPacket(context.Background(), "udp", localAddr.String())
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}
