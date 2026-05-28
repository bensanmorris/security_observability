#include <jni.h>
#include <stdlib.h>
#include <string.h>

/*
 * Uprobe target. eBPF reads buf[0..len-1] at function entry before this
 * body executes. The memory barrier prevents the compiler from eliminating
 * the function or reordering the store of buf across the probe site.
 */
void java_cert_agent_write(const char *buf, int len) {
    (void)buf;
    (void)len;
    asm volatile("" ::: "memory");
}

/*
 * Thread-local buffer. Using __thread avoids GC-visible Java array pinning:
 * GetByteArrayRegion copies bytes into native memory that the GC cannot move,
 * so the pointer passed to java_cert_agent_write is stable at probe entry.
 */
static __thread char *tls_cert_buf = NULL;
static __thread int   tls_cert_buf_size = 0;

static void ensure_tls_buf(int needed) {
    if (tls_cert_buf_size < needed) {
        free(tls_cert_buf);
        tls_cert_buf = malloc((size_t)needed);
        tls_cert_buf_size = tls_cert_buf ? needed : 0;
    }
}

/*
 * JNI entry point called by NativeBridge.writeCertificateBytes(byte[]).
 * Copies the DER byte array into the thread-local buffer and calls the stub.
 */
JNIEXPORT void JNICALL
Java_com_security_certagent_NativeBridge_writeCertificateBytes(
        JNIEnv *env, jclass cls, jbyteArray der) {
    (void)cls;
    if (!der) return;

    jsize len = (*env)->GetArrayLength(env, der);
    if (len <= 0 || len > 65536) return;  /* sanity: DER certs are < 64 KiB */

    ensure_tls_buf((int)len);
    if (!tls_cert_buf) return;

    (*env)->GetByteArrayRegion(env, der, 0, len, (jbyte *)tls_cert_buf);
    if ((*env)->ExceptionCheck(env)) return;

    java_cert_agent_write(tls_cert_buf, (int)len);
}
