//go:build linux || android

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/qtopie/vlink/internal"
	"github.com/qtopie/vlink/v2ray/inbound"
	"golang.org/x/sys/unix"

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
	Config       *TunInboundConfig
	SocksHandler *inbound.SocksInboundHandler
}

type TunInboundConfig struct {
	Name    string
	MTU     int
	FD      int
	Address []string
}

func (h *TunInboundHandler) SetConfig(config *TunInboundConfig) {
	h.Config = config
}

func (h *TunInboundHandler) Start() error {
	// 使用 unix.Dup 复制一个 FD，这样 Go 即使关闭了这个副本，
	// 也不会影响 Java 层的原始 FD，从而避开 fdsan 的检测。
	newFd, err := unix.Dup(h.Config.FD)
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
		FDs: []int{int(file.Fd())},
		MTU: uint32(h.Config.MTU),
	})
	if err != nil {
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

	// 优化缓冲区以提高网速
	opt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min: 4096, Default: 1024 * 1024, Max: 1024 * 1024 * 16,
	}
	netStack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)

	// 4. 配置 NIC
	const nicID = 1
	if err := netStack.CreateNIC(nicID, linkEP); err != nil {
		return fmt.Errorf("create NIC: %v", err)
	}
	netStack.SetPromiscuousMode(nicID, true)
	netStack.SetSpoofing(nicID, true)

	// 设置本地虚拟 IP (避免与 Android 侧 172.19.0.1 冲突)
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4([4]byte{172, 19, 0, 2}).WithPrefix(),
	}
	netStack.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{})

	// 默认路由
	netStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
	})

	// 5. TCP 转发器
	forwarder := tcp.NewForwarder(netStack, 0, 10000, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)

		localAddr, _ := ep.GetLocalAddress()
		destStr := fmt.Sprintf("%s:%d", localAddr.Addr, localAddr.Port)
		conn := gonet.NewTCPConn(&wq, ep)

		if localAddr.Port == 853 || localAddr.Port == 53 {
			go h.simplyForward(conn, localAddr)
			return
		}

		// 分流逻辑：局域网直连，外网走复用的 SocksInboundHandler
		if isLANAddress(localAddr) {
			go h.simplyForward(conn, localAddr)
		} else {
			go h.handleConnection(conn, destStr)
		}
	})
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(netStack, func(r *udp.ForwarderRequest) {
		id := r.ID()

		// 1. 处理所有发往 53 端口的 DNS 请求
		if id.LocalPort == 53 {
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				return
			}

			conn := gonet.NewUDPConn(netStack, &wq, ep)
			go func() {
				defer conn.Close()
				// 重点：使用 net.Dial 发起物理网络直连，绕过 VPN 逻辑
				// 建议使用一个可靠的公网 DNS，如 8.8.8.8 或 1.1.1.1
				remoteConn, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
				if err != nil {
					log.Printf("DNS Direct Dial Error: %v", err)
					return
				}
				defer remoteConn.Close()
				internal.Relay(conn, remoteConn)
			}()
			return
		}

		// 2. (可选) 允许 QUIC 流量尝试直连（避免丢包日志刷屏）
		if id.LocalPort == 443 {
			return
		}
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

	// 1. 使用内存管道，直接跳过网卡层
	c1, c2 := net.Pipe()

	// 2. 将 c2 丢给现有的 SocksInboundHandler.handleConnection 处理
	// 这里会触发你 socks.go 里的 Handshake, dialGRPC, Relay 等所有逻辑
	go h.SocksHandler.DispatchToSocks(c2)

	// 3. 在管道客户端 c1 上执行内存握手
	// 注意：我们要拿回握手成功的那个“包装连接”
	handshakedConn, err := h.bridgeSocks5Client(c1, originalDest)
	if err != nil {
		log.Printf("TUN Bridge: SOCKS5 handshake failed: %v", err)
		c1.Close()
		return
	}

	// 4. 内存 IO 转发：
	// tunConn (来自网卡的原始数据) <-> handshakedConn (已经穿过 SOCKS5 握手层的包装连接)
	internal.Relay(handshakedConn, tunConn)
}

// PipeDialer 让 proxy 包在指定的连接上执行握手，而不是去拨号网络
type PipeDialer struct {
	conn net.Conn
}

func (p *PipeDialer) Dial(network, addr string) (net.Conn, error) {
	return p.conn, nil
}

func (h *TunInboundHandler) bridgeSocks5Client(conn net.Conn, originalDest string) (net.Conn, error) {
	// PipeDialer 确保了 Dial 时不会产生任何网络 IO，全部在 conn (即 c1) 里进行
	pd := &PipeDialer{conn: conn}

	// 创建官方 SOCKS5 客户端逻辑
	dialer, err := proxy.SOCKS5("tcp", "unused:1080", nil, pd)
	if err != nil {
		return nil, err
	}

	// Dial 会在 pd.pipeConn 上发送 [5, 1, 0] 等字节
	// 成功后返回的 proxyConn 包装了原有的 conn，并处理了 SOCKS5 响应头
	proxyConn, err := dialer.Dial("tcp", originalDest)
	if err != nil {
		return nil, err
	}

	return proxyConn, nil
}

// isLANAddress 判断是否是局域网
func isLANAddress(addr tcpip.FullAddress) bool {
	ip := net.ParseIP(addr.Addr.String())
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// simplyForward 直连
func (h *TunInboundHandler) simplyForward(conn net.Conn, remote tcpip.FullAddress) {
	defer conn.Close()
	addr := net.JoinHostPort(remote.Addr.String(), fmt.Sprintf("%d", remote.Port))
	directConn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return
	}
	defer directConn.Close()
	internal.Relay(directConn, conn)
}
