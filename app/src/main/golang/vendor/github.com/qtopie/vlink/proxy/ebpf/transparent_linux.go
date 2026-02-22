//go:build linux && !android
// +build linux,!android

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	soOriginalDst = 80
	solIP         = 0
)

func GetOriginalDst(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a tcp connection")
	}

	f, err := tcpConn.File()
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Restore the blocking mode of the original socket if needed?
	// tcpConn.File() puts the NEW fd in blocking mode. The original fd (in tcpConn) is separate.
	// But we should close the new fd (defer f.Close() handles this).

	fd := int(f.Fd())

	// struct sockaddr_in {
	//    short   sin_family;
	//    u_short sin_port;
	//    struct  in_addr sin_addr;
	//    char    sin_zero[8];
	// };
	// Size is 16 bytes.
	addr := syscall.RawSockaddrInet4{}
	size := uint32(syscall.SizeofSockaddrInet4)

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(solIP),
		uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if errno != 0 {
		return "", errno
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])

	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

func GetOriginalDstUDP(oob []byte) (string, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return "", err
	}

	for _, msg := range msgs {
		if msg.Header.Level == syscall.SOL_IP && msg.Header.Type == syscall.IP_RECVORIGDSTADDR {
			originalDst := &syscall.RawSockaddrInet4{}
			if len(msg.Data) < syscall.SizeofSockaddrInet4 {
				continue
			}
			// Copy data to the struct
			// msg.Data is a byte slice, we need to carefully cast or copy
			// Use unsafe to cast for zero-copy if possible, or simple copy
			// For safety and simplicity in Go:
			copy((*[syscall.SizeofSockaddrInet4]byte)(unsafe.Pointer(originalDst))[:], msg.Data)

			ip := net.IPv4(originalDst.Addr[0], originalDst.Addr[1], originalDst.Addr[2], originalDst.Addr[3])
			port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&originalDst.Port))[:])
			return fmt.Sprintf("%s:%d", ip.String(), port), nil
		}
	}
	return "", fmt.Errorf("original destination not found in OOB data")
}
