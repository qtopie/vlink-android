// +build linux,!android

package main

import (
	"log"
	"os"
	"syscall"
	"unsafe"

	vlinkjni "github.com/qtopierw/workspace/projects/vlink-android/app/src/main/golang"
)

const TUNSETIFF = 0x400454ca

func main() {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("Failed to open /dev/net/tun: %v (Did you use sudo?)", err)
	}

	var ifr [40]byte
	copy(ifr[:16], []byte("vlink0"))
	*(*uint16)(unsafe.Pointer(&ifr[16])) = syscall.IFF_TUN | syscall.IFF_NO_PI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		log.Fatalf("Ioctl failed: %v", errno)
	}

	log.Println("Successfully attached to vlink0")

	config := &vlinkjni.TunInboundConfig{
		Name: "vlink0",
		MTU:  1500,
		FD:   int(file.Fd()),
		Mode: vlinkjni.ModeTun2Direct,
	}

	handler := &vlinkjni.TunInboundHandler{}
	handler.SetConfig(config)

	if err := handler.Start(); err != nil {
		log.Fatalf("Start failed: %v", err)
	}

	log.Println("Vlink is running. Use: curl --interface vlink0 http://1.1.1.1")
	select {}
}
