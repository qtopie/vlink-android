//go:build linux || android

package main

/*
#include <jni.h>

// Forward declaration: protect_fd is implemented in jni_helpers.c
jboolean protect_fd(jint fd);
*/
import "C"

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"syscall"

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
		FDs:               []int{int(file.Fd())},
		MTU:               uint32(h.Config.MTU),
		RXChecksumOffload: true, // 【关键修复】：允许接收 Android TUN 传来的无校验和数据包
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

	// 5. TCP 转发器
	forwarder := tcp.NewForwarder(netStack, 0, 10000, func(r *tcp.ForwarderRequest) {
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

		localAddr, _ := ep.GetLocalAddress()
		destStr := fmt.Sprintf("%s:%d", localAddr.Addr, localAddr.Port)
		conn := gonet.NewTCPConn(&wq, ep)

		if localAddr.Port == 853 || localAddr.Port == 53 {
			log.Printf("TCP Forwarder: DNS/DoT traffic detected, using simplyForward for %s", destStr)
			go h.simplyForward(conn, localAddr)
			return
		}

		// 分流逻辑：局域网直连，外网走复用的 SocksInboundHandler
		if isLANAddress(localAddr) {
			log.Printf("TCP Forwarder: LAN address %s, using simplyForward", destStr)
			go h.simplyForward(conn, localAddr)
		} else {
			log.Printf("TCP Forwarder: Remote address %s, using handleConnection", destStr)
			go h.handleConnection(conn, destStr)
		}
	})
	netStack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(netStack, func(r *udp.ForwarderRequest) {
		id := r.ID()
		log.Printf("UDP Forwarder: incoming connection from %s:%d to %s:%d", id.RemoteAddress, id.RemotePort, id.LocalAddress, id.LocalPort)

		// 1. 处理所有发往 53 端口的 DNS 请求
		if id.LocalPort == 53 {
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				log.Printf("UDP Forwarder: failed to create endpoint for DNS: %v", err)
				return
			}

			conn := gonet.NewUDPConn(netStack, &wq, ep)
			go func() {
				defer conn.Close()
				log.Printf("UDP Forwarder: Dialing DNS 8.8.8.8:53 for %s:%d", id.RemoteAddress, id.RemotePort)
				// 重点：使用 net.Dial 发起物理网络直连，绕过 VPN 逻辑
				// 建议使用一个可靠的公网 DNS，如 8.8.8.8 或 1.1.1.1
				dialer := &net.Dialer{
						Timeout: 2 * time.Second,
						Control: func(network, address string, c syscall.RawConn) error {
							var controlErr error
							if err := c.Control(func(fd uintptr) {
								res := C.protect_fd(C.int(fd))
								if res == 0 {
									log.Printf("TUN protect_fd failed for dns fd %d", fd)
								} else {
									log.Printf("TUN protect_fd succeeded for dns fd %d", fd)
								}
							}); err != nil {
								controlErr = err
							}
							return controlErr
						},
					}
					remoteConn, err := dialer.Dial("udp", "8.8.8.8:53")
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
			log.Printf("UDP Forwarder: ignoring port 443 (QUIC/HTTPS)")
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
	internal.Relay(handshakedConn, tunConn)
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

func (h *TunInboundHandler) bridgeSocks5Client(conn net.Conn, originalDest string) (net.Conn, error) {
	// PipeDialer 确保了 Dial 时不会产生任何网络 IO，全部在 conn (即 c1) 里进行
	pd := &PipeDialer{conn: conn}

	// 创建官方 SOCKS5 客户端逻辑
	dialer, err := proxy.SOCKS5("tcp", "unused:1080", nil, pd)
	if err != nil {
		log.Printf("bridgeSocks5Client: failed to create SOCKS5 dialer: %v", err)
		return nil, err
	}

	// Dial 会在 pd.pipeConn 上发送 [5, 1, 0] 等字节
	// 成功后返回的 proxyConn 包装了原有的 conn，并处理了 SOCKS5 响应头
	log.Printf("bridgeSocks5Client: performing SOCKS5 handshake for %s", originalDest)
	proxyConn, err := dialer.Dial("tcp", originalDest)
	if err != nil {
		return nil, err
	}

	return proxyConn, nil
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
                res := C.protect_fd(C.int(fd))
                if res == 0 {
                    log.Printf("TUN protect_fd failed for fd %d", fd)
                } else {
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
    internal.Relay(directConn, conn)
}