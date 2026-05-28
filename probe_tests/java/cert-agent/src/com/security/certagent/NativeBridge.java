package com.security.certagent;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

public final class NativeBridge {

    private static volatile boolean loaded = false;

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
