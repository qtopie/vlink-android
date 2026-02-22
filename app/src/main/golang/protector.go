package vlinkjni

// SocketProtector is implemented on the Java side and passed into Go via gomobile.
// gomobile will generate a Java interface named vlinkjni.SocketProtector with method
// boolean protect(int fd);
// For desktop Linux builds, cProtectFD is provided by the small C stub (jni_stub.c).
// On Android, cProtectFD is implemented via JNI.

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
// cProtectFD wrapper which is platform-specific (see protector_cgo_*.go).
func protectFD(fd int) bool {
	if socketProtector != nil {
		return socketProtector.Protect(int32(fd))
	}
	return cProtectFD(fd)
}
