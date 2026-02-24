//go:build linux || android

package vlinkjni

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// routeTun2DirectTCP handles direct TCP forwarding for tun2direct mode.
func (h *TunInboundHandler) routeTun2DirectTCP(conn net.Conn, id stack.TransportEndpointID) {
	var remote tcpip.FullAddress
	remote.Addr = id.LocalAddress
	remote.Port = id.LocalPort
	h.simplyForward(conn, remote)
}

// simplyForward 直连
func (h *TunInboundHandler) simplyForward(conn net.Conn, remote tcpip.FullAddress) {
	defer conn.Close()

	// 兼容 gVisor IP 解析
	ipStr := remote.Addr.String()
	if ip := net.ParseIP(ipStr); ip == nil {
		// fall back to using the string as-is
		ipStr = remote.Addr.String()
	}
	addr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", remote.Port))

	log.Printf("TUN 局域网直连: 正在拨号 %s ...", addr)
	remoteCtx := context.Background()
	directConn, err := dialWithProtect(remoteCtx, "tcp", addr, 3*time.Second)
	if err != nil {
		log.Printf("TUN 局域網直連失败! 无法连接到 %s: %v", addr, err)
		return
	}
	defer directConn.Close()

	log.Printf("TUN 局域網直連成功: %s, 开始数据中继", addr)
	relayTCP(directConn, conn)
}

// simplyForwardUDP handles forwarding of UDP flows (e.g., DNS) using UDP dial
func (h *TunInboundHandler) simplyForwardUDP(conn net.Conn, remote tcpip.FullAddress) {
	defer conn.Close()

	ipStr := remote.Addr.String()
	if ip := net.ParseIP(ipStr); ip == nil {
		ipStr = remote.Addr.String()
	}
	addr := net.JoinHostPort(ipStr, fmt.Sprintf("%d", remote.Port))

	log.Printf("TUN UDP 直连: 正在拨号 UDP %s ...", addr)
	// for UDP, use a dialer with protect controls
	netConn, err := dialWithProtect(context.Background(), "udp", addr, 3*time.Second)
	if err != nil {
		log.Printf("TUN UDP 直连失败! 无法连接到 %s: %v", addr, err)
		return
	}
	defer netConn.Close()

	// UDP 是无连接的，使用 deadline 防止僵尸
	netConn.SetDeadline(time.Now().Add(30 * time.Second))
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Use a UDP-aware relay because gonet.NewUDPConn doesn't work well with io.Copy
	relayUDP(netConn, conn)
}
