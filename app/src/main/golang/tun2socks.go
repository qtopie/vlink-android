//go:build linux || android

package vlinkjni

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Metadata is a tiny substitute for tun2socks metadata.Metadata used by direct dialers.
type Metadata struct {
    addr string // host:port
}

func (m *Metadata) DestinationAddress() string { return m.addr }

// Make Metadata from a transport endpoint id (Remote/Local)
func metadataFromID(id interface{}) *Metadata {
    // Try to extract from known gVisor stack.TransportEndpointID
    switch v := id.(type) {
    case stack.TransportEndpointID:
        host := v.LocalAddress.String()
        port := v.LocalPort
        return &Metadata{addr: net.JoinHostPort(host, fmt.Sprintf("%d", port))}
    case *stack.TransportEndpointID:
        host := v.LocalAddress.String()
        port := v.LocalPort
        return &Metadata{addr: net.JoinHostPort(host, fmt.Sprintf("%d", port))}
    case *Metadata:
        return v
    case Metadata:
        return &v
    default:
        return &Metadata{addr: ""}
    }
}

// proxyIface defines the minimal proxy surface used internally by Tunnel
type proxyIface interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
    DialUDP(m *Metadata) (net.PacketConn, error)
}

// SimpleProxy is a trivial implementation that performs direct dialing.
type SimpleProxy struct{}

func newSocks5Proxy(addr, user, pass string) (proxyIface, error) {
    return &Socks5Proxy{addr: addr, user: user, pass: pass}, nil
}

func (s *SimpleProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    d := &net.Dialer{Timeout: 10 * time.Second}
    return d.DialContext(ctx, network, addr)
}

func (s *SimpleProxy) DialUDP(m *Metadata) (net.PacketConn, error) {
    return ListenPacket("udp", "")
}

// Socks5Proxy implements a minimal SOCKS5 client (CONNECT + UDP ASSOCIATE).
type Socks5Proxy struct {
    addr string
    user string
    pass string
}

func (s *Socks5Proxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    // Establish TCP to upstream socks server
    d := &net.Dialer{Timeout: 10 * time.Second}
    conn, err := d.DialContext(ctx, "tcp", s.addr)
    if err != nil {
        return nil, err
    }

    if err := socks5Handshake(conn, s.user, s.pass); err != nil {
        conn.Close()
        return nil, err
    }

    if err := socks5SendCommand(conn, 0x01, addr); err != nil {
        conn.Close()
        return nil, err
    }

    return conn, nil
}

func (s *Socks5Proxy) DialUDP(m *Metadata) (net.PacketConn, error) {
    // Create TCP control connection and perform UDP ASSOCIATE
    d := &net.Dialer{Timeout: 10 * time.Second}
    tcpConn, err := d.Dial("tcp", s.addr)
    if err != nil {
        return nil, err
    }

    if err := socks5Handshake(tcpConn, s.user, s.pass); err != nil {
        tcpConn.Close()
        return nil, err
    }

    // Request UDP ASSOCIATE with DST.ADDR=0.0.0.0:0
    if err := socks5SendUDPAssociate(tcpConn); err != nil {
        tcpConn.Close()
        return nil, err
    }

    // read reply to get relay address
    relayAddr, err := socks5ReadBindAddress(tcpConn)
    if err != nil {
        tcpConn.Close()
        return nil, err
    }

    udpAddr, err := net.ResolveUDPAddr("udp", relayAddr)
    if err != nil {
        tcpConn.Close()
        return nil, err
    }

    // create local UDP socket
    local, err := net.ListenUDP("udp", nil)
    if err != nil {
        tcpConn.Close()
        return nil, err
    }

    pc := &socks5PacketConn{conn: local, relay: udpAddr, ctrl: tcpConn}
    return pc, nil
}

// helper: perform initial socks5 handshake and optional user/pass auth
func socks5Handshake(conn net.Conn, user, pass string) error {
    methods := []byte{0x00}
    if user != "" {
        methods = []byte{0x02, 0x00}
    }
    req := append([]byte{0x05, byte(len(methods))}, methods...)
    if _, err := conn.Write(req); err != nil {
        return err
    }
    resp := make([]byte, 2)
    if _, err := io.ReadFull(conn, resp); err != nil {
        return err
    }
    if resp[0] != 0x05 {
        return fmt.Errorf("socks5: invalid version %d", resp[0])
    }
    method := resp[1]
    if method == 0xFF {
        return fmt.Errorf("socks5: no acceptable auth methods")
    }
    if method == 0x02 {
        // username/password subnegotiation
        if err := socks5UserPassAuth(conn, user, pass); err != nil {
            return err
        }
    }
    return nil
}

func socks5UserPassAuth(conn net.Conn, user, pass string) error {
    ub := []byte(user)
    pb := []byte(pass)
    req := []byte{0x01, byte(len(ub))}
    req = append(req, ub...)
    req = append(req, byte(len(pb)))
    req = append(req, pb...)
    if _, err := conn.Write(req); err != nil {
        return err
    }
    resp := make([]byte, 2)
    if _, err := io.ReadFull(conn, resp); err != nil {
        return err
    }
    if resp[1] != 0x00 {
        return fmt.Errorf("socks5: username/password auth failed")
    }
    return nil
}

func socks5SendCommand(conn net.Conn, cmd byte, dest string) error {
    host, portStr, err := net.SplitHostPort(dest)
    if err != nil {
        return err
    }
    port, _ := strconv.Atoi(portStr)
    var addrBuf []byte
    ip := net.ParseIP(host)
    if ip4 := ip.To4(); ip4 != nil {
        addrBuf = append([]byte{0x01}, ip4...)
    } else if ip6 := ip.To16(); ip6 != nil {
        addrBuf = append([]byte{0x04}, ip6...)
    } else {
        addrBuf = append([]byte{0x03, byte(len(host))}, []byte(host)...)
    }
    portBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(portBuf, uint16(port))
    req := []byte{0x05, cmd, 0x00}
    req = append(req, addrBuf...)
    req = append(req, portBuf...)
    if _, err := conn.Write(req); err != nil {
        return err
    }
    // read reply: VER, REP, RSV, ATYP
    header := make([]byte, 4)
    if _, err := io.ReadFull(conn, header); err != nil {
        return err
    }
    if header[1] != 0x00 {
        return fmt.Errorf("socks5: command failed, code %d", header[1])
    }
    // read BND.ADDR per ATYP
    atyp := header[3]
    switch atyp {
    case 0x01:
        _, _ = io.CopyN(io.Discard, conn, 4+2)
    case 0x03:
        var l [1]byte
        if _, err := io.ReadFull(conn, l[:]); err != nil { return err }
        ln := int(l[0])
        _, _ = io.CopyN(io.Discard, conn, int64(ln+2))
    case 0x04:
        _, _ = io.CopyN(io.Discard, conn, 16+2)
    }
    return nil
}

func socks5SendUDPAssociate(conn net.Conn) error {
    // send UDP ASSOCIATE with 0.0.0.0:0
    req := []byte{0x05, 0x03, 0x00, 0x01, 0,0,0,0, 0,0}
    _, err := conn.Write(req)
    return err
}

func socks5ReadBindAddress(conn net.Conn) (string, error) {
    header := make([]byte, 4)
    if _, err := io.ReadFull(conn, header); err != nil { return "", err }
    if header[1] != 0x00 { return "", fmt.Errorf("socks5: UDP ASSOCIATE failed, code %d", header[1]) }
    atyp := header[3]
    switch atyp {
    case 0x01:
        buf := make([]byte, 4+2)
        if _, err := io.ReadFull(conn, buf); err != nil { return "", err }
        ip := net.IP(buf[:4]).String()
        port := binary.BigEndian.Uint16(buf[4:6])
        return net.JoinHostPort(ip, fmt.Sprintf("%d", port)), nil
    case 0x03:
        var l [1]byte
        if _, err := io.ReadFull(conn, l[:]); err != nil { return "", err }
        name := make([]byte, int(l[0]))
        if _, err := io.ReadFull(conn, name); err != nil { return "", err }
        portBuf := make([]byte,2)
        if _, err := io.ReadFull(conn, portBuf); err != nil { return "", err }
        port := binary.BigEndian.Uint16(portBuf)
        return net.JoinHostPort(string(name), fmt.Sprintf("%d", port)), nil
    case 0x04:
        buf := make([]byte,16+2)
        if _, err := io.ReadFull(conn, buf); err != nil { return "", err }
        ip := net.IP(buf[:16]).String()
        port := binary.BigEndian.Uint16(buf[16:18])
        return net.JoinHostPort(ip, fmt.Sprintf("%d", port)), nil
    default:
        return "", fmt.Errorf("socks5: unknown ATYP %d", atyp)
    }
}

// socks5PacketConn wraps a UDPConn to a SOCKS5 UDP relay and performs
// encapsulation/decapsulation of SOCKS5 UDP datagrams.
type socks5PacketConn struct {
    conn  *net.UDPConn
    relay *net.UDPAddr
    ctrl  net.Conn // keepalive TCP control connection
    mu    sync.Mutex
}

func (s *socks5PacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
    // Read raw packet from relay
    buf := make([]byte, len(b)+64)
    nread, _, err := s.conn.ReadFromUDP(buf)
    if err != nil { return 0, nil, err }
    if nread < 4 { return 0, nil, fmt.Errorf("socks5 udp: short packet") }
    // header: RSV(2), FRAG(1), ATYP
    atyp := buf[3]
    idx := 4
    var src string
    switch atyp {
    case 0x01:
        if nread < idx+4+2 { return 0, nil, fmt.Errorf("socks5 udp: short ipv4") }
        ip := net.IP(buf[idx:idx+4]).String()
        idx += 4
        port := binary.BigEndian.Uint16(buf[idx:idx+2]); idx += 2
        src = net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    case 0x03:
        l := int(buf[idx]); idx++
        if nread < idx+l+2 { return 0, nil, fmt.Errorf("socks5 udp: short domain") }
        name := string(buf[idx:idx+l]); idx += l
        port := binary.BigEndian.Uint16(buf[idx:idx+2]); idx += 2
        src = net.JoinHostPort(name, fmt.Sprintf("%d", port))
    case 0x04:
        if nread < idx+16+2 { return 0, nil, fmt.Errorf("socks5 udp: short ipv6") }
        ip := net.IP(buf[idx:idx+16]).String(); idx += 16
        port := binary.BigEndian.Uint16(buf[idx:idx+2]); idx += 2
        src = net.JoinHostPort(ip, fmt.Sprintf("%d", port))
    default:
        return 0, nil, fmt.Errorf("socks5 udp: unknown atyp %d", atyp)
    }
    // remaining bytes are data
    payload := buf[idx:nread]
    copy(b, payload)
    return len(payload), &net.UDPAddr{IP: net.ParseIP(strings.Split(src, ":")[0]), Port: func() int { p,_:=strconv.Atoi(strings.Split(src, ":")[1]); return p }()}, nil
}

func (s *socks5PacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
    s.mu.Lock(); defer s.mu.Unlock()
    udpAddr, ok := addr.(*net.UDPAddr)
    if !ok {
        return 0, fmt.Errorf("socks5 udp: expected UDPAddr")
    }
    // build header
    var hdr []byte
    hdr = append(hdr, 0x00, 0x00, 0x00)
    if ip4 := udpAddr.IP.To4(); ip4 != nil {
        hdr = append(hdr, 0x01)
        hdr = append(hdr, ip4...)
    } else if ip6 := udpAddr.IP.To16(); ip6 != nil {
        hdr = append(hdr, 0x04)
        hdr = append(hdr, ip6...)
    } else {
        hdr = append(hdr, 0x03, byte(len(udpAddr.IP.String())))
        hdr = append(hdr, []byte(udpAddr.IP.String())...)
    }
    portBuf := make([]byte,2); binary.BigEndian.PutUint16(portBuf, uint16(udpAddr.Port))
    hdr = append(hdr, portBuf...)
    packet := append(hdr, b...)
    _, err = s.conn.WriteToUDP(packet, s.relay)
    if err != nil { return 0, err }
    return len(b), nil
}

func (s *socks5PacketConn) Close() error {
    s.ctrl.Close()
    return s.conn.Close()
}

func (s *socks5PacketConn) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *socks5PacketConn) SetDeadline(t time.Time) error { return s.conn.SetDeadline(t) }
func (s *socks5PacketConn) SetReadDeadline(t time.Time) error { return s.conn.SetReadDeadline(t) }
func (s *socks5PacketConn) SetWriteDeadline(t time.Time) error { return s.conn.SetWriteDeadline(t) }

// RegisterSockOpt registers a socket option callback; no-op for now.
type SocketOptionFunc func(network, address string, rc syscall.RawConn) error

func RegisterSockOpt(_ SocketOptionFunc) {
    // No-op: placeholder to allow tun.go to register protect_fd hooks.
}

// ListenPacket delegates to net.ListenPacket.
func ListenPacket(network, address string) (net.PacketConn, error) {
    return net.ListenPacket(network, address)
}

// Tunnel: minimal handler that accepts adapter connections and dials out.
type Tunnel struct {
    mu                sync.RWMutex
    proxy             proxyIface
    directDialer      func(ctx context.Context, m *Metadata) (net.Conn, error)
    directPacketDial  func(m *Metadata) (net.PacketConn, error)
}

var (
    tunnelOnce sync.Once
    tunnelInst *Tunnel
)

func T() *Tunnel {
    tunnelOnce.Do(func() { tunnelInst = &Tunnel{} })
    return tunnelInst
}

func (t *Tunnel) setProxy(p proxyIface) { t.mu.Lock(); t.proxy = p; t.mu.Unlock() }
func (t *Tunnel) setDirectDialer(f func(ctx context.Context, m *Metadata) (net.Conn, error)) {
    t.mu.Lock(); t.directDialer = f; t.mu.Unlock()
}
func (t *Tunnel) setDirectPacketDialer(f func(m *Metadata) (net.PacketConn, error)) {
    t.mu.Lock(); t.directPacketDial = f; t.mu.Unlock()
}

func (t *Tunnel) ProcessAsync() {
    // no background workers required for this minimal stub
}

// Adapter types: accept any net.Conn that exposes ID() tcpip.TransportEndpointID
type AdapterTCPConn interface {
    net.Conn
    ID() interface{}
}
type AdapterUDPConn interface {
    net.PacketConn
    net.Conn
    ID() interface{}
}

// HandleTCP dials to destination and relays between the provided adapter conn and remote.
func (t *Tunnel) handleTCP(c AdapterTCPConn) {
    go func() {
        id := c.ID()
        m := metadataFromID(id)

        var remote net.Conn
        var err error
        // prefer direct dialer if set
        t.mu.RLock()
        dd := t.directDialer
        px := t.proxy
        t.mu.RUnlock()

        ctx := context.Background()
        if dd != nil {
            remote, err = dd(ctx, m)
        } else if px != nil {
            remote, err = px.DialContext(ctx, "tcp", m.DestinationAddress())
        } else {
            remote, err = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", m.DestinationAddress())
        }
        if err != nil {
            _ = c.Close()
            log.Printf("Tunnel HandleTCP: dial failed: %v", err)
            return
        }

        // Relay both directions with half-close semantics.
        var wg sync.WaitGroup
        wg.Add(2)

        go func() {
            defer wg.Done()
            _, _ = io.Copy(remote, c)
            if cw, ok := remote.(interface{ CloseWrite() error }); ok {
                _ = cw.CloseWrite()
            } else {
                _ = remote.Close()
            }
        }()

        go func() {
            defer wg.Done()
            _, _ = io.Copy(c, remote)
            if cw, ok := c.(interface{ CloseWrite() error }); ok {
                _ = cw.CloseWrite()
            } else {
                _ = c.Close()
            }
        }()

        wg.Wait()
    }()
}

// HandleUDP establishes a remote packet connection and proxies datagrams.
func (t *Tunnel) handleUDP(c AdapterUDPConn) {
    go func() {
        id := c.ID()
        m := metadataFromID(id)

        t.mu.RLock()
        dp := t.directPacketDial
        px := t.proxy
        t.mu.RUnlock()

        var pc net.PacketConn
        var err error
        if dp != nil {
            pc, err = dp(m)
        } else if px != nil {
            pc, err = px.DialUDP(m)
        } else {
            pc, err = ListenPacket("udp", "")
        }
        if err != nil {
            _ = c.Close()
            log.Printf("Tunnel HandleUDP: dial/listen failed: %v", err)
            return
        }

        // Simple forwarding: read from adapter PacketConn and write to remote, and vice versa.
        var wg sync.WaitGroup
        wg.Add(2)

        destAddrStr := m.DestinationAddress()
        destUDPAddr, _ := net.ResolveUDPAddr("udp", destAddrStr)

        go func() {
            defer wg.Done()
            buf := make([]byte, 65535)
            for {
                n, from, err := c.ReadFrom(buf)
                if err != nil {
                    return
                }
                if n > 0 {
                    // write to proxy packet conn with destination
                    _, _ = pc.WriteTo(buf[:n], destUDPAddr)
                    _ = from // read source ignored for now
                }
            }
        }()

        go func() {
            defer wg.Done()
            buf := make([]byte, 65535)
            for {
                n, addr, err := pc.ReadFrom(buf)
                if err != nil {
                    return
                }
                if n > 0 {
                    // write back into adapter with source address
                    _, _ = c.WriteTo(buf[:n], addr)
                }
            }
        }()

        // keep alive briefly
        time.AfterFunc(30*time.Second, func() { pc.Close(); c.Close() })
        wg.Wait()
    }()
}
