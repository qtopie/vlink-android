#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#define LOG_TAG "vlink"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

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
