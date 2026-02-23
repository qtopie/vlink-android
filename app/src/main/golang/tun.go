//go:build linux || android

package vlinkjni

// Note: cgo declarations for protect_fd are split into platform-specific files
// protector_cgo_linux.go and protector_cgo_android.go to avoid referencing jni.h on desktop.

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/qtopie/vlink/v2ray/inbound"
	"golang.org/x/sys/unix"

	"net/url"
	// Local tun2socks-compatible stubs will be provided in tun2socks.go
	"golang.org/x/net/proxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type TunInboundHandler struct {
	config *TunInboundConfig
	SocksHandler *inbound.SocksInboundHandler
}

const (
	ModeTun2Direct       = "tun2direct"
	ModeTun2SocksUpstream = "tun2socksUpstream"
	ModeTun2SocksInbound  = "tun2socksInbound"
)

type TunInboundConfig struct {
	Name          string
	MTU           int
	FD            int
	Address       []string
	UpstreamSocks string
	// Mode controls how TUN traffic is forwarded.
	// Allowed: ModeTun2Direct (default), ModeTun2SocksUpstream, ModeTun2SocksInbound
	Mode          string
}

// wrapper to satisfy tun2socks adapter.TCPConn
type adapterTCPConn struct {
	*gonet.TCPConn
	id *stack.TransportEndpointID
}

func (c *adapterTCPConn) ID() interface{} { return c.id }

// wrapper to satisfy tun2socks adapter.UDPConn (both net.Conn and net.PacketConn)
type adapterUDPConn struct {
	pc  net.PacketConn
	c   net.Conn
	id  *stack.TransportEndpointID
}

func (u *adapterUDPConn) ID() interface{} { return u.id }

func (u *adapterUDPConn) Close() error {
	if u.c != nil {
		return u.c.Close()
	}
	if u.pc != nil {
		return u.pc.Close()
	}
	return nil
}

func (u *adapterUDPConn) LocalAddr() net.Addr {
	if u.c != nil {
		return u.c.LocalAddr()
	}
	if u.pc != nil {
		return u.pc.LocalAddr()
	}
	return nil
}

func (u *adapterUDPConn) RemoteAddr() net.Addr {
	if u.c != nil {
		return u.c.RemoteAddr()
	}
	// PacketConn does not usually provide RemoteAddr; return nil.
	return nil
}

func (u *adapterUDPConn) Read(b []byte) (int, error) {
	if u.c != nil {
		return u.c.Read(b)
	}
	return 0, fmt.Errorf("no underlying Conn for Read")
}

func (u *adapterUDPConn) Write(b []byte) (int, error) {
	if u.c != nil {
		return u.c.Write(b)
	}
	return 0, fmt.Errorf("no underlying Conn for Write")
}

func (u *adapterUDPConn) SetDeadline(t time.Time) error {
	if u.c != nil {
		return u.c.SetDeadline(t)
	}
	if u.pc != nil {
		return u.pc.SetDeadline(t)
	}
	return nil
}

func (u *adapterUDPConn) SetReadDeadline(t time.Time) error {
	if u.c != nil {
		return u.c.SetReadDeadline(t)
	}
	if u.pc != nil {
		return u.pc.SetReadDeadline(t)
	}
	return nil
}

func (u *adapterUDPConn) SetWriteDeadline(t time.Time) error {
	if u.c != nil {
		return u.c.SetWriteDeadline(t)
	}
	if u.pc != nil {
		return u.pc.SetWriteDeadline(t)
	}
	return nil
}

func (u *adapterUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if u.pc != nil {
		return u.pc.ReadFrom(p)
	}
	return 0, nil, fmt.Errorf("no underlying PacketConn for ReadFrom")
}

func (u *adapterUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if u.pc != nil {
		return u.pc.WriteTo(p, addr)
	}
	return 0, fmt.Errorf("no underlying PacketConn for WriteTo")
}

func (h *TunInboundHandler) SetConfig(config *TunInboundConfig) {
	h.config = config
}

func (h *TunInboundHandler) Start() error {
	// 使用 unix.Dup 复制一个 FD，这样 Go 即使关闭了这个副本，
	// 也不会影响 Java 层的原始 FD，从而避开 fdsan 的检测, 避免影响java进程
	newFd, err := unix.Dup(h.config.FD)
	if err != nil {
		return fmt.Errorf("failed to dup fd: %v", err)
	}

	// 设置 FD 为非阻塞模式 (gVisor 强制要求)
	if err := unix.SetNonblock(newFd, true); err != nil {
		return fmt.Errorf("set nonblock: %v", err)
	}
	file := os.NewFile(uintptr(newFd), "tun")

	// 2. 初始化 gVisor Link Endpoint
	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:               []int{int(file.Fd())},
		MTU:               uint32(h.config.MTU),
		RXChecksumOffload: true,
	})
	if err != nil {
		log.Printf("TUN Inbound: failed to create link endpoint: %v", err)
		return err
	}

	// 3. 创建网络协议栈
	netStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})
	reuseOpt := tcpip.TCPTimeWaitReuseOption(1)
	netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &reuseOpt)

	// 优化缓冲区以提高网速
	opt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min: 4096, Default: 1024 * 1024, Max: 1024 * 1024 * 16,
	}
	netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)

	// 4. 配置 NIC
	const nicID = 1
	if err := netStack.CreateNIC(nicID, linkEP); err != nil {
		log.Printf("TUN Inbound: failed to create NIC: %v", err)
		return fmt.Errorf("create NIC: %v", err)
	}
	netStack.SetPromiscuousMode(nicID, true)
	netStack.SetSpoofing(nicID, true)

	// 设置本地虚拟 IP 地址（必须在 Android TUN 的子网范围内）
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{172, 19, 0, 2}),
			PrefixLen: 30,
		},
	}
	if err := netStack.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		log.Printf("TUN Inbound: failed to add protocol address: %v", err)
	}

	// 默认路由
	netStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	// Decide forwarding mode (default: tun2direct)
	mode := ModeTun2Direct
	if h.config != nil && h.config.Mode != "" {
		mode = h.config.Mode
	}

	// Register a default direct dialer that uses VpnService.protect via protectFD
	T().setDirectDialer(func(ctx context.Context, m *Metadata) (net.Conn, error) {
		nd := &net.Dialer{
			Timeout: 3 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				var controlErr error
				if err := c.Control(func(fd uintptr) {
					if !protectFD(int(fd)) {
						controlErr = fmt.Errorf("TUN protect_fd failed for fd %d", fd)
						return
					}
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}); err != nil {
					controlErr = err
				}
				return controlErr
			},
		}
		return nd.DialContext(ctx, "tcp", m.DestinationAddress())
	})
	T().setDirectPacketDialer(func(m *Metadata) (net.PacketConn, error) {
		return ListenPacket("udp", "")
	})

	// If upstream socks is configured and mode is tun2socksUpstream, parse it and set tunnel global proxy.
	if mode == ModeTun2SocksUpstream && h.config != nil && h.config.UpstreamSocks != "" {
		up := h.config.UpstreamSocks
		if !strings.Contains(up, "://") {
			up = "socks5://" + up
		}
		u, err := url.Parse(up)
		if err != nil {
			log.Printf("TUN: invalid upstream socks %s: %v", up, err)
		} else {
			addr := u.Host
			user := ""
			pass := ""
			if u.User != nil {
				user = u.User.Username()
				pass, _ = u.User.Password()
			}
			p, err := newSocks5Proxy(addr, user, pass)
			if err != nil {
				log.Printf("TUN: failed to create upstream proxy: %v", err)
			} else {
				T().setProxy(p)
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
					// dial directly to destination
					nd := &net.Dialer{
						Timeout: 3 * time.Second,
						Control: func(network, address string, c syscall.RawConn) error {
							var controlErr error
							if err := c.Control(func(fd uintptr) {
								if !protectFD(int(fd)) {
								if res == 0 {
									controlErr = fmt.Errorf("TUN protect_fd failed for fd %d", fd)
									return
								}
								_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
							}); err != nil {
								controlErr = err
							}
							return controlErr
						},
					}
					return nd.DialContext(ctx, "tcp", m.DestinationAddress())
				})
				T().setDirectPacketDialer(func(m *Metadata) (net.PacketConn, error) {
					// create a UDP packet conn for direct UDP
					return ListenPacket("udp", "")
				})
			}
		}
	}

	// 5. TCP 转发器
	// Ensure tunnel processing is running
	T().ProcessAsync()

	tcpForwarder := tcp.NewForwarder(netStack, 0, 10000, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		log.Printf("TCP Forwarder: connection from %s:%d to %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("TCP Forwarder: failed to create endpoint: %v", err)
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)

		// capture id by value and take address to satisfy adapter interface
		idVal := id
		wrapped := &adapterTCPConn{TCPConn: conn, id: &idVal}
		// Hand off to tunnel which will use the configured proxy for dialing
		T().handleTCP(wrapped)
		// 		// 分流逻辑：局域网直连，外网走复用的 SocksInboundHandler
		// 		if isLANAddress(localAddr) {
		// 			log.Printf("TCP Forwarder: LAN address %s, using simplyForward", destStr)
		// 			go h.simplyForward(conn, localAddr)
		// 		} else {
		// 			log.Printf("TCP Forwarder: Remote address %s, using handleConnection", destStr)
		// 			go h.handleConnection(conn, destStr)
		// 		}
	})
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(netStack, func(r *udp.ForwarderRequest) {
		id := r.ID()
		log.Printf("UDP Forwarder: incoming connection from %s:%d to %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)

		// 		// 1. 处理所有发往 53 端口的 DNS 请求
		// 		if id.LocalPort == 53 {
		// 			log.Printf("UDP Forwarder: DNS traffic detected, using simplyForwardUDP for %s:%d", id.LocalAddress, id.LocalPort)
		// 			var wq waiter.Queue
		// 			ep, err := r.CreateEndpoint(&wq)
		// 			if err != nil {
		// 				log.Printf("UDP Forwarder: failed to create endpoint: %v", err)
		// 				return
		// 			}
		//
		// 			localAddr, _ := ep.GetLocalAddress()
		// 			conn := gonet.NewUDPConn(netStack, &wq, ep)
		// 			go h.simplyForwardUDP(conn, localAddr)
		// 			return
		// 		}

		// Create endpoint and hand to tunnel as adapter.UDPConn
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Printf("UDP Forwarder: failed to create endpoint: %v", err)
			return
		}

		pc := gonet.NewUDPConn(netStack, &wq, ep)

		idVal := id
		wrappedUDP := &adapterUDPConn{pc: pc, c: pc, id: &idVal}
		T().handleUDP(wrappedUDP)
		return

		// 		// 2. (可选) 允许 QUIC 流量尝试直连（避免丢包日志刷屏）
		// 		if id.LocalPort == 443 {
		// 			log.Printf("UDP Forwarder: ignoring port 443 (QUIC/HTTPS)")
		// 			return
		// 		}
	})
	netStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	log.Printf("TUN Inbound started. Bridging to SocksInboundHandler...")
	return nil
}

// 核心桥接方法
func (h *TunInboundHandler) handleConnection(tunConn net.Conn, originalDest string) {
	defer tunConn.Close()

	if h.SocksHandler == nil {
		log.Println("TUN Inbound error: SocksHandler not initialized")
		return
	}

	log.Printf("TUN Bridge: Received connection for %s", originalDest)

	// 1. 使用内存管道，直接跳过网卡层
	c1, c2 := net.Pipe()

	// 2. 将 c2 丢给现有的 SocksInboundHandler.handleConnection 处理
	// 这里会触发你 socks.go 里的 Handshake, dialGRPC, Relay 等所有逻辑
	log.Printf("TUN Bridge: Dispatching to SocksInboundHandler for %s", originalDest)
	go h.SocksHandler.DispatchToSocks(c2)

	// 3. 在管道客户端 c1 上执行内存握手
	// 注意：我们要拿回握手成功的那个“包装连接”
	handshakedConn, err := h.bridgeSocks5Client(c1, originalDest)
	if err != nil {
		log.Printf("TUN Bridge: SOCKS5 handshake failed for %s: %v", originalDest, err)
		c1.Close()
		return
	}

	log.Printf("TUN Bridge: SOCKS5 handshake successful for %s, starting relay", originalDest)

	// 4. 内存 IO 转发：
	// tunConn (来自网卡的原始数据) <-> handshakedConn (已经穿过 SOCKS5 握手层的包装连接)
	h.relay(handshakedConn, tunConn)
	log.Printf("TUN Bridge: Relay finished for %s", originalDest)
}

// PipeDialer 让 proxy 包在指定的连接上执行握手，而不是去拨号网络
type PipeDialer struct {
	conn net.Conn
}

func (p *PipeDialer) Dial(network, addr string) (net.Conn, error) {
	log.Printf("PipeDialer: Dialing %s on memory pipe", addr)
	return p.conn, nil
}

// netDialerAdapter wraps *net.Dialer to implement golang.org/x/net/proxy.Dialer
type netDialerAdapter struct {
	d *net.Dialer
}

func (n *netDialerAdapter) Dial(network, addr string) (net.Conn, error) {
	return n.d.Dial(network, addr)
}

func (h *TunInboundHandler) bridgeSocks5Client(conn net.Conn, originalDest string) (net.Conn, error) {
	// Use in-memory pipe dialer to perform SOCKS5 handshake on provided conn.
	pd := &PipeDialer{conn: conn}

	dialer, err := proxy.SOCKS5("tcp", "unused:1080", nil, pd)
	if err != nil {
		log.Printf("bridgeSocks5Client: failed to create SOCKS5 dialer: %v", err)
		return nil, err
	}

	log.Printf("bridgeSocks5Client: performing SOCKS5 handshake for %s", originalDest)
	proxyConn, err := dialer.Dial("tcp", originalDest)
	if err != nil {
		return nil, err
	}

	return proxyConn, nil
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

// isLANAddress 判断是否是局域网
func isLANAddress(addr tcpip.FullAddress) bool {
	ipStr := addr.Addr.String()
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// gVisor 兼容性回退：如果 String() 解析失败，尝试转换为 IPv4 字节
		if len(ipStr) == 4 {
			ip = net.IPv4(ipStr[0], ipStr[1], ipStr[2], ipStr[3])
		} else {
			log.Printf("TUN 分流警告: 无法解析 IP 地址 [%q]", ipStr)
			return false
		}
	}

	isPrivate := ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
	log.Printf("TUN 分流判断: %s -> 是否为局域网: %v", ip.String(), isPrivate)
	return isPrivate
}

// simplyForward 直连
func (h *TunInboundHandler) simplyForward(conn net.Conn, remote tcpip.FullAddress) {
	defer conn.Close()

	// 兼容 gVisor IP 解析
	ipStr := remote.Addr.String()
	if ip := net.ParseIP(ipStr); ip == nil && len(ipStr) == 4 {
		ipStr = net.IPv4(ipStr[0], ipStr[1], ipStr[2], ipStr[3]).String()
	}
	addr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", remote.Port))

	log.Printf("TUN 局域网直连: 正在拨号 %s ...", addr)
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				if !protectFD(int(fd)) {
				if res == 0 {
					log.Printf("TUN protect_fd failed for fd %d", fd)
				} else {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					log.Printf("TUN protect_fd succeeded for fd %d", fd)
				}
			}); err != nil {
				controlErr = err
			}
			return controlErr
		},
	}
	directConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("TUN 局域网直连失败! 无法连接到 %s: %v", addr, err)
		return
	}
	defer directConn.Close()

	log.Printf("TUN 局域网直连成功: %s, 开始数据中继", addr)
	h.relay(directConn, conn)
}

// simplyForwardUDP handles forwarding of UDP flows (e.g., DNS) using UDP dial
func (h *TunInboundHandler) simplyForwardUDP(conn net.Conn, remote tcpip.FullAddress) {
	defer conn.Close()

	// 兼容 gVisor IP 解析
	ipStr := remote.Addr.String()
	if ip := net.ParseIP(ipStr); ip == nil && len(ipStr) == 4 {
		ipStr = net.IPv4(ipStr[0], ipStr[1], ipStr[2], ipStr[3]).String()
	}
	addr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", remote.Port))

	log.Printf("TUN UDP 直连: 正在拨号 UDP %s ...", addr)
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				if !protectFD(int(fd)) {
				if res == 0 {
					log.Printf("TUN protect_fd failed for fd %d", fd)
				} else {
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					log.Printf("TUN protect_fd succeeded for fd %d", fd)
				}
			}); err != nil {
				controlErr = err
			}
			return controlErr
		},
	}

	remoteConn, err := dialer.Dial("udp", addr)
	if err != nil {
		log.Printf("TUN UDP 直连失败! 无法连接到 %s: %v", addr, err)
		return
	}
	defer remoteConn.Close()

	// UDP 是无连接的，使用 deadline 防止僵尸
	remoteConn.SetDeadline(time.Now().Add(30 * time.Second))
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Use a UDP-aware relay because gonet.NewUDPConn doesn't work well with io.Copy
	h.relayUDP(remoteConn, conn)
}

// relayUDP forwards datagrams between a remote UDP socket and a local gonet UDPConn.
// This avoids using io.Copy which is incompatibile with gVisor's datagram semantics.
// relayUDP 双向转发 UDP 数据报，修复了共享缓冲区的并发写入问题
func (h *TunInboundHandler) relayUDP(remote, local net.Conn) {
    var wg sync.WaitGroup
    wg.Add(2)

    // 本地 TUN -> 远端网络
    go func() {
        defer wg.Done()
        defer remote.Close() // 退出时清理
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
        defer local.Close() // 退出时清理
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


// relay 双向转发 TCP 数据流，支持半关闭 (Half-Close)
func (h *TunInboundHandler) relay(left, right net.Conn) {
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
