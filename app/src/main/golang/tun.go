//go:build linux || android

package vlinkjni

// Note: cgo declarations for protect_fd are split into platform-specific files
// protector_cgo_linux.go and protector_cgo_android.go to avoid referencing jni.h on desktop.

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/qtopie/vlink/v2ray/inbound"
	"golang.org/x/sys/unix"

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
	config       *TunInboundConfig
	SocksHandler *inbound.SocksInboundHandler
}

const (
	ModeTun2Direct        = "tun2direct"
	ModeTun2SocksUpstream = "tun2socksUpstream"
	ModeTun2V2rayInbound  = "tun2v2rayInbound"
)

type TunInboundConfig struct {
	Name          string
	MTU           int
	FD            int
	Address       []string
	UpstreamSocks string
	// Mode controls how TUN traffic is forwarded.
	// Allowed: ModeTun2Direct (default), ModeTun2SocksUpstream, ModeTun2V2rayInbound
	Mode string
}

// wrapper to satisfy tun2socks adapter.TCPConn
type adapterTCPConn struct {
	*gonet.TCPConn
	id *stack.TransportEndpointID
}

func (c *adapterTCPConn) ID() interface{} { return c.id }

// wrapper to satisfy tun2socks adapter.UDPConn (both net.Conn and net.PacketConn)
type adapterUDPConn struct {
	pc net.PacketConn
	c  net.Conn
	id *stack.TransportEndpointID
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
		return dialWithProtect(ctx, "tcp", m.DestinationAddress(), 3*time.Second)
	})
	T().setDirectPacketDialer(func(m *Metadata) (net.PacketConn, error) {
		return dialPacketWithProtect("udp", "")
	})

	if mode == ModeTun2SocksUpstream {
		if err := configureUpstreamSocks(h); err != nil {
			log.Printf("TUN: configure upstream socks failed: %v", err)
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
		// Dispatch by configured mode
		switch mode {
		case ModeTun2Direct:
			// For direct mode, hand raw gonet conn to direct handler
			go h.routeTun2DirectTCP(conn, id)
		case ModeTun2SocksUpstream:
			// Upstream mode: delegate to mode-specific router which may perform extra logic
			h.routeTun2SocksUpstreamTCP(wrapped)
		case ModeTun2V2rayInbound:
			// Inbound mode: hand raw gonet conn to local socks inbound bridge
			orig := fmt.Sprintf("%s:%d", id.LocalAddress, id.LocalPort)
			go h.routeTun2V2rayInboundTCP(conn, orig)
		default:
			T().handleTCP(wrapped)
		}
	})
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(netStack, func(r *udp.ForwarderRequest) {
		id := r.ID()
		log.Printf("UDP Forwarder: incoming connection from %s:%d to %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)

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
		// Dispatch UDP handling by configured mode
		switch mode {
		case ModeTun2Direct:
			// For direct mode, attempt to forward UDP directly (e.g., DNS)
			var remote tcpip.FullAddress
			remote.Addr = id.LocalAddress
			remote.Port = id.LocalPort
			go h.simplyForwardUDP(wrappedUDP.c, remote)
		case ModeTun2SocksUpstream:
			// Upstream mode: delegate to mode-specific upstream UDP handler
			go h.routeTun2SocksUpstreamUDP(wrappedUDP)
		default:
			// Inbound and other modes use tunnel's UDP handler
			T().handleUDP(wrappedUDP)
		}
	})
	netStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	log.Printf("TUN Inbound started. Bridging to SocksInboundHandler...")
	return nil
}
