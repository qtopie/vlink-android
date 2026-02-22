package inbound

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	vlinkcore "github.com/qtopie/vlink/core"
	"github.com/qtopie/vlink/internal"
	"github.com/qtopie/vlink/socks"
	grpcpkg "github.com/qtopie/vlink/v2ray/transport/grpc"
)

var (
	ErrUnsupportedCommand = errors.New("unsupported SOCKS command")
	ErrUnsupportedAddress = errors.New("unsupported SOCKS address type")
	ErrInvalidSOCKSFormat = errors.New("invalid SOCKS format")
)

// SocksInboundHandler 实现 v2ray.com/core/app/proxyman/inbound.Handler
type SocksInboundHandler struct {
	net.Listener
	config *InboundConfig // SOCKS5 配置结构体
}

// SetConfig 设置配置
func (h *SocksInboundHandler) SetConfig(config *InboundConfig) {
	h.config = config
}

// Start 启动 Inbound 监听
func (h *SocksInboundHandler) Start() error {
	// 已持有 Core 上下文

	addr := net.JoinHostPort(h.config.ListenAddress, strconv.Itoa(int(h.config.ListenPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.Listener = ln

	// 监听循环
	go func() {
		for {
			conn, err := h.Listener.Accept()
			if err != nil {
				// 忽略监听器关闭或临时错误
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					continue
				}
				return
			}
			go h.DispatchToSocks(conn)
		}
	}()
	return nil
}

func (h *SocksInboundHandler) DispatchToSocks(conn net.Conn) {
	defer conn.Close()

	// 1. SOCKS5 握手和地址解析
	addr, err := socks.Handshake(conn)
	if err != nil {
		log.Println("CustomSOCKS5: SOCKS5 handshake failed:", err)
		return
	}

	log.Printf("SOCKS Handshake target: %s", addr)

	// 2. 从 ServerManager 获取当前最佳服务器
	bestServer := h.config.ServerManager.GetBestServer()
	if bestServer == "" {
		log.Println("CustomSOCKS5: no available server from manager")
		return
	}

	// 3. 创建 gRPC 连接
	rc, err := h.dialGRPC(bestServer)
	if err != nil {
		log.Printf("CustomSOCKS5: failed to connect to server %s via gRPC: %v", bestServer, err)
		return
	}
	defer rc.Close()

	// 4. 使用 cipher 包装连接
	if h.config.Cipher != nil {
		if cipher, ok := h.config.Cipher.(vlinkcore.StreamConnCipher); ok {
			rc = cipher.StreamConn(rc)
		}
	}

	// 5. 发送目标地址到 shadowsocks 服务器
	if _, err = rc.Write(addr); err != nil {
		log.Println("CustomSOCKS5: failed to send target address:", err)
		return
	}

	log.Printf("CustomSOCKS5: proxy %s <-> %s <-> %s (gRPC)",
		conn.RemoteAddr(), bestServer, addr)

	// 6. 双向转发流量
	if err = internal.Relay(rc, conn); err != nil {
		// Do not log "use of closed network connection" errors, as they are expected
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Println("CustomSOCKS5: relay error:", err)
		}
	}
}

// dialGRPC 创建 gRPC 连接
func (h *SocksInboundHandler) dialGRPC(serverAddress string) (net.Conn, error) {
	host := h.config.Host
	if host == "" {
		// 如果没有指定 host，尝试从 ServerAddress 中提取
		if strings.Contains(serverAddress, ":") {
			host = strings.Split(serverAddress, ":")[0]
		} else {
			host = serverAddress
		}
	}

	log.Printf("CustomSOCKS5: Attempting gRPC dial with params: serverAddress=%s, host=%s, serviceName=%s, TLS=%t",
		serverAddress, host, h.config.ServiceName, h.config.TLS)

	// 使用配置的 TLS 设置
	return grpcpkg.DialDirectContext(
		context.Background(),
		serverAddress,
		host,
		h.config.ServiceName,
		h.config.TLS,
	)
}

// Close 关闭监听器
func (h *SocksInboundHandler) Close() {
	if h.Listener != nil {
		h.Listener.Close()
	}
}

// --- 注册 Inbound Factory ---
func init() {}
