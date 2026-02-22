//go:build !linux && !android
// +build !linux,!android

package ebpf

import (
	"errors"
	"net"
)

func GetOriginalDst(conn net.Conn) (string, error) {
	return "", errors.New("not supported on this os")
}

func GetOriginalDstUDP(oob []byte) (string, error) {
	return "", errors.New("not supported on this os")
}
