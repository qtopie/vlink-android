//go:build linux || android

package vlinkjni

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// isLANAddress 判断是否是局域网
func isLANAddress(addr tcpip.FullAddress) bool {
	ipStr := addr.Addr.String()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// gVisor 兼容性回退：如果 String() 解析失败，无法解析则认为非局域网
		log.Printf("TUN 分流警告: 无法解析 IP 地址 [%q]", ipStr)
		return false
	}

	isPrivate := ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
	log.Printf("TUN 分流判断: %s -> 是否为局域网: %v", ip.String(), isPrivate)
	return isPrivate
}


// dialWithProtect dials a network address using protection hooks (protectFD and
// any registered RegisterSockOpt hooks). It returns a net.Conn or error.
func dialWithProtect(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	nd := &net.Dialer{Timeout: timeout}
	nd.Control = func(network, address string, c syscall.RawConn) error {
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			// primary protection
			if !protectFD(int(fd)) {
				controlErr = fmt.Errorf("TUN protect_fd failed for fd %d", fd)
				return
			}
			// set reuseaddr as before
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		// apply any registered sock opts
		if err := globalTunnel.applySockOpts(network, address, c); err != nil {
			return err
		}
		return controlErr
	}
	return nd.DialContext(ctx, network, address)
}

// dialPacketWithProtect creates a PacketConn using ListenPacket or dialer hooks.
func dialPacketWithProtect(network, addr string) (net.PacketConn, error) {
	return ListenPacket(network, addr)
}

// Tunnel manager: provides dialers and handlers used by tun.go.
// This is a functional implementation replacing earlier stubs.

type Metadata struct {
	destination string
}

func (m *Metadata) DestinationAddress() string { return m.destination }

func metadataFromEndpoint(id *stack.TransportEndpointID) *Metadata {
	addr := id.LocalAddress.String()
	port := id.LocalPort
	return &Metadata{destination: net.JoinHostPort(addr, fmt.Sprintf("%d", port))}
}

type sockOptFunc func(_, _ string, rc syscall.RawConn) error

type tunnel struct {
	mu                 sync.RWMutex
	directDialer       func(context.Context, *Metadata) (net.Conn, error)
	directPacketDialer func(*Metadata) (net.PacketConn, error)
	proxy              interface{}
	sockOpts           []sockOptFunc
}

var globalTunnel = &tunnel{}

func T() *tunnel { return globalTunnel }

func (t *tunnel) setDirectDialer(fn func(context.Context, *Metadata) (net.Conn, error)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.directDialer = fn
}
func (t *tunnel) setDirectPacketDialer(fn func(*Metadata) (net.PacketConn, error)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.directPacketDialer = fn
}
func (t *tunnel) setProxy(p interface{}) { t.mu.Lock(); defer t.mu.Unlock(); t.proxy = p }

// RegisterSockOpt appends a socket option hook which will be invoked by the
// tunnel when creating outbound sockets. Multiple hooks are supported.
func RegisterSockOpt(fn func(_, _ string, rc syscall.RawConn) error) {
	globalTunnel.mu.Lock()
	defer globalTunnel.mu.Unlock()
	globalTunnel.sockOpts = append(globalTunnel.sockOpts, fn)
}

// ProcessAsync is a no-op placeholder for compatibility. Real implementations
// may start background workers here.
func (t *tunnel) ProcessAsync() {}

// helper to run all registered sock opts on a syscall.RawConn
func (t *tunnel) applySockOpts(network, address string, rc syscall.RawConn) error {
	t.mu.RLock()
	opts := append([]sockOptFunc(nil), t.sockOpts...)
	t.mu.RUnlock()
	for _, fn := range opts {
		if err := fn(network, address, rc); err != nil {
			return err
		}
	}
	return nil
}

// handleTCP accepts an adapterTCPConn (as interface{}) and dials the remote
// endpoint using the configured directDialer (or net.Dial fallback) then
// relays traffic between the two connections. It prefers the configured
// upstream proxy (if any) for non-LAN destinations.
func (t *tunnel) handleTCP(w interface{}) {
	wrapped, ok := w.(*adapterTCPConn)
	if !ok {
		return
	}

	idIface := wrapped.ID()
	if idIface == nil {
		log.Println("tunnel: missing transport endpoint id")
		_ = wrapped.Close()
		return
	}
	idPtr, ok := idIface.(*stack.TransportEndpointID)
	if !ok {
		log.Println("tunnel: unexpected ID type")
		_ = wrapped.Close()
		return
	}

	m := metadataFromEndpoint(idPtr)
	ctx := context.Background()

	// Determine if destination is LAN; if so prefer direct dialer
	isLAN := isLANAddress(tcpip.FullAddress{Addr: idPtr.LocalAddress, Port: idPtr.LocalPort})

	t.mu.RLock()
	dialer := t.directDialer
	proxyIface := t.proxy
	t.mu.RUnlock()

	var remote net.Conn
	var err error

	// If proxy configured and destination not LAN, try proxy first
	if proxyIface != nil && !isLAN {
		if pd, ok := proxyIface.(interface {
			Dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)
		}); ok {
			remote, err = pd.Dial(ctx, "tcp", m.DestinationAddress(), 5*time.Second)
		} else if pd2, ok := proxyIface.(interface {
			DialTCP(ctx context.Context, targetAddr string, timeout time.Duration) (net.Conn, error)
		}); ok {
			remote, err = pd2.DialTCP(ctx, m.DestinationAddress(), 5*time.Second)
		} else {
			// unknown proxy type, fall back to direct
			if dialer != nil {
				remote, err = dialer(ctx, m)
			} else {
				remote, err = net.DialTimeout("tcp", m.DestinationAddress(), 5*time.Second)
			}
		}
		if err != nil {
			log.Printf("tunnel: proxy dial error to %s: %v; falling back to direct", m.DestinationAddress(), err)
			// try direct
			if dialer != nil {
				remote, err = dialer(ctx, m)
			} else {
				remote, err = net.DialTimeout("tcp", m.DestinationAddress(), 5*time.Second)
			}
		}
	} else {
		if dialer != nil {
			remote, err = dialer(ctx, m)
		} else {
			remote, err = net.DialTimeout("tcp", m.DestinationAddress(), 5*time.Second)
		}
	}
	if err != nil {
		log.Printf("tunnel: dial error to %s: %v", m.DestinationAddress(), err)
		_ = wrapped.Close()
		return
	}

	setKeepAlive(remote)

	// Relay between remote and local (wrapped implements net.Conn via gonet)
	relayConn(remote, wrapped)
}

// handleUDP accepts an adapterUDPConn and dials a remote UDP endpoint then
// forwards datagrams in both directions using relayUDP.
func (t *tunnel) handleUDP(w interface{}) {
	wrapped, ok := w.(*adapterUDPConn)
	if !ok {
		return
	}

	idIface := wrapped.ID()
	if idIface == nil {
		log.Println("tunnel: missing transport endpoint id (udp)")
		_ = wrapped.Close()
		return
	}
	idPtr, ok := idIface.(*stack.TransportEndpointID)
	if !ok {
		log.Println("tunnel: unexpected ID type (udp)")
		_ = wrapped.Close()
		return
	}

	m := metadataFromEndpoint(idPtr)

	// Dial a UDP connection to the destination. Use control hooks if available.
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	dialer.Control = func(network, address string, rc syscall.RawConn) error {
		return t.applySockOpts(network, address, rc)
	}

	// Determine if destination is LAN; if so prefer direct dialer
	isLAN := isLANAddress(tcpip.FullAddress{Addr: idPtr.LocalAddress, Port: idPtr.LocalPort})

	t.mu.RLock()
	proxyIface := t.proxy
	t.mu.RUnlock()

	var remote net.Conn
	var err error
	if proxyIface != nil && !isLAN {
		if pd, ok := proxyIface.(interface {
			Dial(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error)
		}); ok {
			remote, err = pd.Dial(context.Background(), "udp", m.DestinationAddress(), 3*time.Second)
		} else if pd2, ok := proxyIface.(interface {
			DialUDP(ctx context.Context, targetAddr string, timeout time.Duration) (net.Conn, error)
		}); ok {
			remote, err = pd2.DialUDP(context.Background(), m.DestinationAddress(), 3*time.Second)
		} else {
			remote, err = dialer.Dial("udp", m.DestinationAddress())
		}
		if err != nil {
			log.Printf("tunnel: proxy udp dial error to %s: %v; falling back to direct", m.DestinationAddress(), err)
			// try direct
			remote, err = dialer.Dial("udp", m.DestinationAddress())
		}
	} else {
		remote, err = dialer.Dial("udp", m.DestinationAddress())
	}

	if err != nil {
		log.Printf("tunnel: udp dial error to %s: %v", m.DestinationAddress(), err)
		_ = wrapped.Close()
		return
	}

	// local connection (adapterUDPConn exposes net.Conn via c)
	local := net.Conn(nil)
	if wrapped.c != nil {
		local = wrapped.c
	} else {
		// no underlying net.Conn available
		_ = remote.Close()
		return
	}

	// set deadlines conservative
	remote.SetDeadline(time.Now().Add(60 * time.Second))
	local.SetDeadline(time.Now().Add(60 * time.Second))

	relayUDP(remote, local)
}

func relayConn(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = ioCopy(right, left)
		if cw, ok := right.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = right.Close()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = ioCopy(left, right)
		if cw, ok := left.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = left.Close()
		}
	}()

	wg.Wait()
}

// Small helpers to avoid importing io in many places; use io.Copy semantics.
func ioCopy(dst net.Conn, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			wn, werr := dst.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == net.ErrClosed || err == syscall.ECONNRESET || err == syscall.EINVAL {
				return total, err
			}
			return total, err
		}
	}
}

// Keep compatibility helpers used by tun.go
func ListenPacket(network, addr string) (net.PacketConn, error) {
	return net.ListenPacket(network, addr)
}


// relayUDP forwards datagrams between a remote UDP socket and a local gonet UDPConn.
// This avoids using io.Copy which is incompatibile with gVisor's datagram semantics.
// relayUDP 双向转发 UDP 数据报，修复了共享缓冲区的并发写入问题
func relayUDP(remote, local net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// 本地 TUN -> 远端网络
	go func() {
		defer wg.Done()
		defer remote.Close()      // 退出时清理
		buf := make([]byte, 4096) // 独立内存，最大 MTU 支持
		for {
			_ = local.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = remote.Write(buf[:n])
			}
		}
	}()

	// 远端网络 -> 本地 TUN
	go func() {
		defer wg.Done()
		defer local.Close()       // 退出时清理
		buf := make([]byte, 4096) // 独立内存
		for {
			_ = remote.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := remote.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = local.Write(buf[:n])
			}
		}
	}()

	wg.Wait()
}

// relayTCP 双向转发 TCP 数据流，支持半关闭 (Half-Close)
func relayTCP(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// left -> right
	go func() {
		defer wg.Done()
		_, _ = io.Copy(right, left)
		// left 停止发送了，告诉 right 我们不再写入
		if cw, ok := right.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = right.Close()
		}
	}()

	// right -> left
	go func() {
		defer wg.Done()
		_, _ = io.Copy(left, right)
		// right 停止发送了，告诉 left 我们不再写入
		if cw, ok := left.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = left.Close()
		}
	}()

	wg.Wait()
}

// setKeepAlive enables TCP keepalive and sets a sane period when possible.
func setKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// safeConnClose closes the connection only when an error occurred during the
// surrounding operation (mirrors the original intent of SafeConnClose).
func safeConnClose(c net.Conn, err error) {
	if err != nil && c != nil {
		_ = c.Close()
	}
}
