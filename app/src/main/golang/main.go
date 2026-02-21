package main

/*
#include <jni.h>
#include <stdlib.h>
#include <android/log.h>

#define LOG_TAG "vlink"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Helper to get string from JNI
static const char* get_string(JNIEnv* env, jstring str) {
    if (str == NULL) return NULL;
    return (*env)->GetStringUTFChars(env, str, NULL);
}

static void release_string(JNIEnv* env, jstring str, const char* chars) {
    if (str == NULL || chars == NULL) return;
    (*env)->ReleaseStringUTFChars(env, str, chars);
}

static void log_to_android(const char* msg) {
    LOGI("%s", msg);
}

// Global storage for JavaVM and a global ref to VlinkVpnService class.
static JavaVM* global_vm = NULL;
static jclass global_vlinkvpnservice_cls = NULL;

// Store JavaVM and a global reference to the VlinkVpnService class for later use from native threads.
// Accept either a jobject (instance) or jclass; if an instance is passed, obtain its class.
void store_java_vm(JNIEnv* env, jobject obj) {
    if (global_vm == NULL) {
        (*env)->GetJavaVM(env, &global_vm);
    }
    if (global_vlinkvpnservice_cls == NULL && obj != NULL) {
        jclass cls = (*env)->GetObjectClass(env, obj);
        if (cls != NULL) {
            global_vlinkvpnservice_cls = (jclass)(*env)->NewGlobalRef(env, cls);
            (*env)->DeleteLocalRef(env, cls);
        }
    }
}

// Protect a socket FD by calling VlinkVpnService.protectFd(int) (static).
// Returns JNI_TRUE on success, JNI_FALSE on failure.
jboolean protect_fd(jint fd) {
    if (global_vm == NULL || global_vlinkvpnservice_cls == NULL) return JNI_FALSE;
    JNIEnv* env;
    if ((*global_vm)->AttachCurrentThread(global_vm, &env, NULL) != 0) {
        return JNI_FALSE;
    }
    jmethodID mid = (*env)->GetStaticMethodID(env, global_vlinkvpnservice_cls, "protectFd", "(I)Z");
    if (mid == NULL) {
        (*global_vm)->DetachCurrentThread(global_vm);
        return JNI_FALSE;
    }
    jboolean res = (*env)->CallStaticBooleanMethod(env, global_vlinkvpnservice_cls, mid, fd);
    (*global_vm)->DetachCurrentThread(global_vm);
    return res;
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/qtopie/vlink/core"
	vlink "github.com/qtopie/vlink/internal"
	"github.com/qtopie/vlink/internal/servermanager"
	"github.com/qtopie/vlink/v2ray/inbound"
)

const defaultGRPCUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"

//export Java_com_github_shadowsocks_plugin_v2ray_VlinkVpnService_startVLinkNative
func Java_com_github_shadowsocks_plugin_v2ray_VlinkVpnService_startVLinkNative(
	env *C.JNIEnv,
	clazz C.jobject,
	fd C.jint,
	serverStr C.jstring,
	hostStr C.jstring,
	userAgentStr C.jstring,
	serviceNameStr C.jstring,
	tunAddrStr C.jstring,
	tunMTU C.jint,
	verbose C.jboolean,
	logPathStr C.jstring,
) {
	C.log_to_android(C.CString("JNI: startVLinkNative entered"))
	C.store_java_vm(env, clazz)

	// Convert JNI strings to Go strings
	cLogPath := C.get_string(env, logPathStr)
	defer C.release_string(env, logPathStr, cLogPath)
	goLogPath := C.GoString(cLogPath)

	if goLogPath != "" {
		C.log_to_android(C.CString("JNI: Redirecting log to " + goLogPath))
		f, err := os.OpenFile(goLogPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err == nil {
			log.SetOutput(f)
			log.Println("--- Go Engine Log Initialized ---")
		} else {
			C.log_to_android(C.CString("JNI: Failed to open log file: " + err.Error()))
		}
	}

	cServer := C.get_string(env, serverStr)
	defer C.release_string(env, serverStr, cServer)
	goServer := C.GoString(cServer)

	cHost := C.get_string(env, hostStr)
	defer C.release_string(env, hostStr, cHost)
	goHost := C.GoString(cHost)

	cUserAgent := C.get_string(env, userAgentStr)
	defer C.release_string(env, userAgentStr, cUserAgent)
	goUserAgent := C.GoString(cUserAgent)

	cServiceName := C.get_string(env, serviceNameStr)
	defer C.release_string(env, serviceNameStr, cServiceName)
	goServiceName := C.GoString(cServiceName)

	cTunAddr := C.get_string(env, tunAddrStr)
	defer C.release_string(env, tunAddrStr, cTunAddr)
	goTunAddr := C.GoString(cTunAddr)

	goTunFD := int(fd)
	goTunMTU := int(tunMTU)
	goVerbose := verbose != 0

	if goVerbose {
		vlink.SetVerbose(true)
	}

	// Start in a goroutine to not block the JNI call
	go func() {
		log.Printf("vlink Goroutine: Started (FD: %d, MTU: %d, TunAddr: %s)", goTunFD, goTunMTU, goTunAddr)
		C.log_to_android(C.CString("Goroutine: Starting TUN handler..."))

		server, cipher, pass, err := parseServerUrl(goServer)
		if err != nil {
			log.Printf("vlink: Error parsing server URL '%s': %v", goServer, err)
			return
		}
		log.Printf("vlink: Parsed server address: %s, cipher: %s", server, cipher)

		if goUserAgent == "" {
			goUserAgent = defaultGRPCUserAgent
		}
		os.Setenv("GRPC_USER_AGENT", goUserAgent)

		ciph, err := core.PickCipher(cipher, nil, pass)
		if err != nil {
			log.Printf("vlink Error: pick cipher '%s': %v", cipher, err)
			return
		}

		log.Printf("vlink: Starting TUN inbound. SNI Host: %s, ServiceName: %s", goHost, goServiceName)

		// Initialize and start the ServerManager with the initial server(s).
		log.Printf("vlink: Initializing ServerManager with server %s", server)
		sm := servermanager.New([]string{server}, 10*time.Minute, 2*time.Second) // Long interval for regular checks
		sm.Start()
// 		go servermanager.RunCDNScanner(sm, goHost, 443)

		// 3. 初始化 SocksInboundHandler 的配置
		log.Printf("vlink: Configuring SocksInboundHandler (TLS: true, Host: %s)", goHost)
		sconf := &inbound.InboundConfig{
			ListenAddress: "127.0.0.1",
			ListenPort:    0, // 内存桥接模式，端口设为 0 即可
			Cipher:        ciph,
			Host:          goHost,        // 远程服务器的 SNI/Host
			ServiceName:   goServiceName, // gRPC 服务名
			TLS:           true,
			SkipVerify:    false,
			ServerManager: sm,
		}
		socksHandler := &inbound.SocksInboundHandler{}
		socksHandler.SetConfig(sconf)

		// 4. 初始化 TunInboundHandler
		tconf := &TunInboundConfig{
			FD:      goTunFD,
			Address: []string{goTunAddr},
			MTU:     goTunMTU,
		}

		tunHandler := &TunInboundHandler{
			Config:       tconf,
			SocksHandler: socksHandler,
		}

		log.Printf("vlink: Starting TunInboundHandler...")
		if err := tunHandler.Start(); err != nil {
			log.Printf("vlink: Failed to start TUN handler: %v", err)
			return
		}

		log.Printf("vlink: TUN handler started successfully. Entering wait state.")
		// resources will be closed automatically
		select {}
	}()
}

// parseServerUrl extracts network addresses and assumes a common cipher/password from a list of ss:// URLs.
func parseServerUrl(server string) (address string, cipher, password string, err error) {
	if server == "" {
		return "", "", "", fmt.Errorf("server address is empty")
	}
	// Use the provided server entry to parse details
	address, cipher, password, err = vlink.ParseURL(server)
	return
}

func main() {}
