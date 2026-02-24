//go:build linux || android

package vlinkjni

import (
	"log"
	"net"

	"github.com/qtopie/vlink/v2ray/inbound"
	"golang.org/x/net/proxy"
)

// routeTun2V2rayInboundTCP forwards connections to the local SocksInbound bridge.
func (h *TunInboundHandler) routeTun2V2rayInboundTCP(conn net.Conn, originalDest string) {
	log.Printf("tun2v2ray: routing to SocksInbound for %s", originalDest)
	handleConnection(h.SocksHandler, conn, originalDest)
}

// handleConnection is the SOCKS inbound bridge used by tun2v2rayInbound mode.
func handleConnection(v2rayInboundHandler *inbound.SocksInboundHandler, tunConn net.Conn, originalDest string) {
	defer tunConn.Close()

	if v2rayInboundHandler == nil {
		log.Println("TUN Inbound error: SocksHandler not initialized")
		return
	}

	log.Printf("TUN Bridge: Received connection for %s", originalDest)

	// 1. 使用内存管道，直接跳过网卡层
	c1, c2 := net.Pipe()

	// 2. 将 c2 丢给现有的 SocksInboundHandler.handleConnection 处理
	// 这里会触发你 socks.go 里的 Handshake, dialGRPC, Relay 等所有逻辑
	log.Printf("TUN Bridge: Dispatching to SocksInboundHandler for %s", originalDest)
	go v2rayInboundHandler.DispatchToSocks(c2)

	// 3. 在管道客户端 c1 上执行内存握手
	// 注意：我们要拿回握手成功的那个“包装连接”
	handshakedConn, err := bridgeSocks5Client(c1, originalDest)
	if err != nil {
		log.Printf("TUN Bridge: SOCKS5 handshake failed for %s: %v", originalDest, err)
		c1.Close()
		return
	}

	log.Printf("TUN Bridge: SOCKS5 handshake successful for %s, starting relay", originalDest)

	// 4. 内存 IO 转发：tunConn (来自网卡的原始数据) <-> handshakedConn (已经穿过 SOCKS5 握手层的包装连接)
	relayTCP(handshakedConn, tunConn)
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

func bridgeSocks5Client(conn net.Conn, originalDest string) (net.Conn, error) {
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
