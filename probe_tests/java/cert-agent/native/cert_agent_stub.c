#include <jni.h>
#include <stdlib.h>
#include <string.h>

/*
 * Uprobe target. eBPF reads buf[0..len-1] at function entry before this
 * body executes.
 *
 * The asm constraint lists buf and len as explicit inputs ("r"), forcing GCC
 * to load them into registers before the asm site. Without this, GCC emits
 * only `retq` as the first instruction (the function body is semantically
 * empty), which breaks uprobe attachment: the kernel's uprobe infrastructure
 * replaces the first byte with int3, but a retq-first function causes Tetragon
 * to read zero or garbage for char_buf arguments because the CPU register state
 * at the int3 site is ambiguous for a bare-retq stub.
 *
 * With "r"(buf) and "r"(len) as inputs the compiler must emit at least a
 * sub/push prologue before the asm, giving the uprobe a stable attach point
 * and guaranteeing RDI=buf, RSI=len at function entry as the x86-64 ABI
 * requires.
 */
__attribute__((noinline))
void java_cert_agent_write(const char *buf, int len) {
    /* volatile write forces a stack store before retq, giving the uprobe a
     * non-retq first instruction. Without this GCC emits only `retq` (the
     * function body is semantically empty), which causes Tetragon to read
     * zero bytes for the char_buf arg at the uprobe site. */
    volatile int _len = len;
    (void)buf;
    (void)_len;
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
