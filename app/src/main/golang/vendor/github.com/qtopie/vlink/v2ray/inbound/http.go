package inbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	vlinkcore "github.com/qtopie/vlink/core"
	"github.com/qtopie/vlink/internal"
	"github.com/qtopie/vlink/internal/router"
	"github.com/qtopie/vlink/socks"
	grpcpkg "github.com/qtopie/vlink/v2ray/transport/grpc" // Added for gRPC dial
)

// HTTPProxyHandler implements an HTTP proxy inbound handler.
type HTTPProxyHandler struct {
	net.Listener
	config *InboundConfig // Use proxy.InboundConfig
}

// SetConfig sets the configuration for the handler.
func (h *HTTPProxyHandler) SetConfig(config *InboundConfig) {
	h.config = config
}

// Start starts the inbound listener.
func (h *HTTPProxyHandler) Start() error {
	addr := net.JoinHostPort(h.config.ListenAddress, strconv.Itoa(int(h.config.ListenPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	h.Listener = ln

	go func() {
		for {
			conn, err := h.Listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					continue
				}
				return
			}
			go h.handleConnection(conn)
		}
	}()
	return nil
}

func (h *HTTPProxyHandler) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF {
			log.Println("CustomHTTP: Failed to read HTTP request:", err)
		}
		return
	}

	isConnect := req.Method == http.MethodConnect

	targetHost, targetPort, err := resolveTarget(req)
	if err != nil {
		log.Printf("CustomHTTP: failed to resolve target from request: %v", err)
		writeHTTPError(conn, http.StatusBadRequest)
		return
	}

	// Dynamic routing decision
	if h.config.EnableAutoProxy && h.config.RuleManager != nil {
		action := h.config.RuleManager.Match(targetHost)
		log.Printf("CustomHTTP: Host '%s' matched rule action: %s", targetHost, action.String())

		if action == router.ActionDirect {
			log.Printf("CustomHTTP: Direct connecting to %s:%s", targetHost, targetPort)
			remoteConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 5*time.Second) // 5 second timeout for direct connection
			if err != nil {
				log.Printf("CustomHTTP: Failed to direct connect to %s:%s: %v", targetHost, targetPort, err)
				writeHTTPError(conn, http.StatusBadGateway)
				return
			}
			defer remoteConn.Close()

			if isConnect {
				if err := writeConnectEstablished(conn); err != nil {
					log.Println("CustomHTTP: Failed to write CONNECT response:", err)
					return
				}
			} else {
				sanitizeRequest(req)
				err = req.Write(remoteConn)
				if err != nil {
					log.Println("CustomHTTP: Failed to write request to direct remote:", err)
					return
				}
			}

			log.Printf("CustomHTTP: direct %s <-> %s", conn.RemoteAddr(), remoteConn.RemoteAddr())
			if err = internal.Relay(remoteConn, conn); err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Println("CustomHTTP: direct relay error:", err)
				}
			}
			return // Handled by direct connection
		}
	}

	// Fallback to proxying via global gRPC upstream (mimicking SOCKS5 handler)
	bestServer := h.config.ServerManager.GetBestServer()
	if bestServer == "" {
		log.Println("CustomHTTP: no available server from manager")
		writeHTTPError(conn, http.StatusBadGateway)
		return
	}

	// 1. Dial gRPC
	upstreamConn, err := h.dialGRPC(bestServer)
	if err != nil {
		log.Printf("CustomHTTP: failed to connect to server %s via gRPC: %v", bestServer, err)
		writeHTTPError(conn, http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// 2. Wrap Cipher
	if h.config.Cipher != nil {
		if cipher, ok := h.config.Cipher.(vlinkcore.StreamConnCipher); ok {
			upstreamConn = cipher.StreamConn(upstreamConn)
		}
	}

	// 3. Send Target Address (SOCKS5 format)
	targetAddr := socks.ParseAddr(net.JoinHostPort(targetHost, targetPort))
	if targetAddr == nil {
		log.Printf("CustomHTTP: failed to parse target address %s:%s", targetHost, targetPort)
		writeHTTPError(conn, http.StatusBadRequest)
		return
	}
	if _, err = upstreamConn.Write(targetAddr); err != nil {
		log.Println("CustomHTTP: failed to send target address:", err)
		return
	}

	if isConnect {
		if err := writeConnectEstablished(conn); err != nil {
			log.Println("CustomHTTP: Failed to write CONNECT response:", err)
			return
		}
	} else {
		sanitizeRequest(req)
		err = req.Write(upstreamConn)
		if err != nil {
			log.Println("CustomHTTP: Failed to write original HTTP request to upstream:", err)
			return
		}
	}

	log.Printf("CustomHTTP: proxy %s <-> %s (gRPC) <-> %s:%s",
		conn.RemoteAddr(), bestServer, targetHost, targetPort)

	if err = internal.Relay(upstreamConn, conn); err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Println("CustomHTTP: relay error:", err)
		}
	}
}

// dialGRPC dials the upstream server via gRPC
func (h *HTTPProxyHandler) dialGRPC(serverAddress string) (net.Conn, error) {
	host := h.config.Host
	if host == "" {
		if strings.Contains(serverAddress, ":") {
			host = strings.Split(serverAddress, ":")[0]
		} else {
			host = serverAddress
		}
	}

	return grpcpkg.DialDirectContext(
		context.Background(),
		serverAddress,
		host,
		h.config.ServiceName,
		h.config.TLS,
	)
}

func resolveTarget(req *http.Request) (string, string, error) {
	hostPort := req.URL.Host
	if hostPort == "" {
		hostPort = req.Host
	}
	if hostPort == "" && req.Method == http.MethodConnect {
		hostPort = req.RequestURI
	}
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return "", "", fmt.Errorf("empty host in request")
	}

	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			defaultPort := "80"
			if req.Method == http.MethodConnect {
				defaultPort = "443"
			}
			host = hostPort
			port = defaultPort
		} else {
			return "", "", err
		}
	}

	if host == "" {
		return "", "", fmt.Errorf("empty host after parse")
	}

	return host, port, nil
}

func writeHTTPError(conn net.Conn, status int) {
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
}

func writeConnectEstablished(conn net.Conn) error {
	_, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	return err
}

func sanitizeRequest(req *http.Request) {
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Connection")
}

// Close closes the listener.
func (h *HTTPProxyHandler) Close() {
	if h.Listener != nil {
		h.Listener.Close()
	}
}
