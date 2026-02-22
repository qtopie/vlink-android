//go:build android
// +build android

package vlinkjni

/*
#include <jni.h>
// Forward declaration: protect_fd implemented in jni_helpers.c
jboolean protect_fd(jint fd);
*/
import "C"

func cProtectFD(fd int) bool {
	return int(C.protect_fd(C.int(fd))) != 0
}
