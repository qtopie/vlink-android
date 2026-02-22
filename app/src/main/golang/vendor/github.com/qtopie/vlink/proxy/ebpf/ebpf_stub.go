//go:build !linux && !android
// +build !linux,!android

package ebpf

import "syscall"

func Setup(proxyPort int) error {
	return nil
}

func Close() {
}

func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	return nil
}
