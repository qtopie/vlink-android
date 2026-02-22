package internal

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/qtopie/vlink/socks"
)

// SocksLocal creates a SOCKS server listening on addr and proxy to server.
func SocksLocal(addr, server string, shadow func(net.Conn) net.Conn) {
	logDebugf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(addr, server, shadow, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) })
}

// tcpLocal listens on addr and proxy to server to reach target from getAddr.
func tcpLocal(addr, server string, shadow func(net.Conn) net.Conn, getAddr func(net.Conn) (socks.Addr, error)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logDebugf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logDebugf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tgt, err := getAddr(c)
			if err != nil {
				logDebugf("failed to get target address: %v", err)
				return
			}

			rc, err := net.Dial("tcp", server)
			if err != nil {
				logDebugf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			rc = shadow(rc)

			if _, err = rc.Write(tgt); err != nil {
				logDebugf("failed to send target address: %v", err)
				return
			}

			logDebugf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			if err = Relay(rc, c); err != nil {
				logDebugf("relay error: %v", err)
			}
		}()
	}
}

// TCPRemote listens on addr for incoming connections.
func TCPRemote(addr string, shadow func(net.Conn) net.Conn) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logDebugf("failed to listen on %s: %v", addr, err)
		return
	}

	logDebugf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logDebugf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()
			sc := shadow(c)

			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				logDebugf("failed to get target address from %v: %v", c.RemoteAddr(), err)
				// drain c to avoid leaking server behavioral features
				// see https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
				_, err = io.Copy(io.Discard, c)
				if err != nil {
					logDebugf("discard error: %v", err)
				}
				return
			}

			rc, err := net.Dial("tcp", tgt.String())
			if err != nil {
				logDebugf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			logDebugf("proxy %s <-> %s", c.RemoteAddr(), tgt)
			if err = Relay(sc, rc); err != nil {
				logDebugf("relay error: %v", err)
			}
		}()
	}
}

// aLongTimeAgo is a non-zero time in the past used to immediately unblock Read/Write deadlines.
var aLongTimeAgo = time.Unix(1, 0)

// relay copies between left and right bidirectionally
func Relay(left, right net.Conn) error {
	var wg sync.WaitGroup
	var err, err1 error
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(right, left)
		right.SetReadDeadline(aLongTimeAgo)
		logDebugf(">>> TUN -> SOCKS: copied %d bytes, err: %v", n, err)
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(left, right)
		left.SetReadDeadline(aLongTimeAgo)
		logDebugf("<<< SOCKS -> TUN: copied %d bytes, err: %v", n, err)
	}()

	wg.Wait()

	if err != nil && !isIgnorableError(err) {
		return err
	}
	if err1 != nil && !isIgnorableError(err1) {
		return err1
	}
	return nil
}

// isIgnorableError checks if an error is an expected close signal (EOF or timeout).
func isIgnorableError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	return false
}
