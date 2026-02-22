package vlinkjni

/*
#include <jni.h>

// Forward declaration to allow fallback to existing JNI helper if no Go-side protector is set.
jboolean protect_fd(jint fd);
*/
import "C"

// SocketProtector is implemented on the Java side and passed into Go via gomobile.
// gomobile will generate a Java interface named vlinkjni.SocketProtector with method
// boolean protect(int fd);
type SocketProtector interface {
	Protect(fd int32) bool
}

var socketProtector SocketProtector

// SetSocketProtector is exposed to Java by gomobile. Call this from your VpnService
// to hand the Service instance (which implements the generated SocketProtector interface).
func SetSocketProtector(p SocketProtector) {
	socketProtector = p
}

// protectFD tries the Go-side socketProtector first; if absent, falls back to the
// JNI helper (old C implementation) for backwards compatibility.
func protectFD(fd int) bool {
	if socketProtector != nil {
		return socketProtector.Protect(int32(fd))
	}
	res := C.protect_fd(C.int(fd))
	return res != 0
}
