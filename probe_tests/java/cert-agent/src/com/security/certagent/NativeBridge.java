package com.security.certagent;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public final class NativeBridge {

    private static volatile boolean loaded = false;

    static {
        // Runs when this class is first loaded by ANY classloader — including the
        // bootstrap classloader that loads it when the instrumented
        // KeyStore.setCertificateEntry first executes its invokestatic call here.
        //
        // CertAgent.setup() stores the .so path in this property before calling
        // appendToBootstrapClassLoaderSearch, so the property is visible when the
        // bootstrap classloader initialises this class.  Without this, the bootstrap
        // copy of NativeBridge would have loaded=false (the loadLibrary() call in
        // setup() only initialises the agent-classloader copy) and reportCertificate
        // would silently return early on every setCertificateEntry invocation.
        String libPath = System.getProperty("com.security.certagent.lib");
        if (libPath != null) {
            try {
                System.load(libPath);
                loaded = true;
            } catch (UnsatisfiedLinkError e) {
                System.err.println("[cert-agent] Static init: failed to load native stub: " + e.getMessage());
            }
        }
    }

    static void loadLibrary(String libPath) {
        if (loaded) return;
        try {
            System.load(libPath);
            loaded = true;
        } catch (UnsatisfiedLinkError e) {
            System.err.println("[cert-agent] Failed to load native stub: " + e.getMessage());
        }
    }

    /**
     * Called from instrumented code. Encodes the certificate to DER and passes
     * the bytes to the native uprobe stub. Exceptions are swallowed so that
     * native-library failures do not affect the observed application.
     */
    public static void reportCertificate(Certificate cert) {
        if (!loaded || cert == null) return;
        try {
            writeCertificateBytes(cert.getEncoded());
        } catch (CertificateEncodingException | RuntimeException ignored) {
        }
    }

    private static native void writeCertificateBytes(byte[] der);

    private NativeBridge() {}
}
