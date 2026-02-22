//go:build linux && !android
// +build linux,!android

package ebpf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -output-dir . bpf bpf/redirect.c

const (
	bypassMark = 0xff
)

var (
	bpfLink link.Link
	bpfObjs bpfObjects
	enabled atomic.Bool
)

func Setup(proxyPort int) error {
	// 1. 解除内存锁定限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("loading spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"proxy_port":  uint32(proxyPort),
		"bypass_mark": uint32(bypassMark),
	}); err != nil {
		return fmt.Errorf("rewriting constants: %v", err)
	}

	// 将修改后的 spec 载入内核
	if err := spec.LoadAndAssign(&bpfObjs, nil); err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}

	// Create and/or attach to cgroup
	// We need a cgroup v2 unified hierarchy.
	// We assume /sys/fs/cgroup is the mount point.

	cgroupRoot := "/sys/fs/cgroup"
	vproxyCgroup := filepath.Join(cgroupRoot, "vproxy")

	if err := os.MkdirAll(vproxyCgroup, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup: %v", err)
	}

	// Open the cgroup directory
	f, err := os.Open(vproxyCgroup)
	if err != nil {
		return fmt.Errorf("opening cgroup: %v", err)
	}
	defer f.Close()

	// Attach the eBPF program to the cgroup
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    vproxyCgroup,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: bpfObjs.Sock4Connect,
	})
	if err != nil {
		return fmt.Errorf("attaching cgroup: %v", err)
	}
	bpfLink = l

	// Add the current process to the cgroup
	// This ensures that all child processes (exec'd command) are also in the cgroup.
	// The proxy itself is also in the cgroup, BUT it uses SO_MARK to bypass.

	pid := os.Getpid()
	if err := os.WriteFile(filepath.Join(vproxyCgroup, "cgroup.procs"), []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("adding pid to cgroup: %v", err)
	}

	enabled.Store(true)
	log.Printf("eBPF enabled: Redirecting to port %d, bypass mark 0x%x", proxyPort, bypassMark)
	return nil
}

func Close() {
	if bpfLink != nil {
		bpfLink.Close()
	}
	bpfObjs.Close()
	enabled.Store(false)
}

func GetDialerControl() func(network, address string, c syscall.RawConn) error {
	if !enabled.Load() {
		return nil
	}
	
	return func(network, address string, c syscall.RawConn) error {
		var opErr error
		err := c.Control(func(fd uintptr) {
			// Set SO_MARK to bypassMark
			// SOL_SOCKET = 1, SO_MARK = 36 (on Linux)
			// We can use syscall package constants
			err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, bypassMark)
			if err != nil {
				opErr = err
			}
		})
		if err != nil {
			return err
		}
		return opErr
	}
}
