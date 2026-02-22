//go:build linux && !android
// +build linux,!android

package vlinkjni

/*
// Declaration for the C stub provided in jni_stub.c
int protect_fd(int fd);
*/
import "C"

func cProtectFD(fd int) bool {
	return int(C.protect_fd(C.int(fd))) != 0
}
