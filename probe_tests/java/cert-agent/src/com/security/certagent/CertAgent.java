package com.security.certagent;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.nio.file.Paths;
import java.util.jar.JarFile;

/**
 * Java agent for non-FIPS certificate interception.
 *
 * Instruments KeyStore.setCertificateEntry to capture certificate DER bytes
 * through a native uprobe stub (java_cert_agent_write in libcert_agent_stub.so).
 * Tetragon attaches a uprobe to that stub and emits events that
 * cert_analyzer._handle_uprobe_in_memory_cert processes identically to
 * SSL_CTX_use_certificate_ASN1 events from OpenSSL.
 *
 * Usage:
 *   Static:  -javaagent:/opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so
 *   Dynamic: jattach <pid> load instrument false \
 *              /opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so
 *
 * The agentArgs string (after '=') is the absolute path to libcert_agent_stub.so.
 * If omitted, the agent looks for the .so adjacent to its own JAR file.
 */
public class CertAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        setup(agentArgs, inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        setup(agentArgs, inst);
    }

    private static void setup(String agentArgs, Instrumentation inst) {
        String libPath = resolveLibPath(agentArgs);
        if (libPath == null) {
            System.err.println("[cert-agent] Cannot find libcert_agent_stub.so — aborting");
            return;
        }

        // Publish the .so path BEFORE addAgentJarToBootstrap and without calling
        // NativeBridge.loadLibrary() here.  The JVM allows a native library to be
        // associated with only one ClassLoader; calling System.load from the agent
        // classloader first causes the bootstrap classloader's attempt (via
        // NativeBridge's static initializer) to fail with "already loaded in another
        // classloader", leaving loaded=false in the bootstrap copy that KeyStore
        // actually calls.  By skipping the agent-classloader load and letting the
        // static initializer fire exclusively from the bootstrap context, System.load
        // succeeds there and loaded=true in the right copy.
        System.setProperty("com.security.certagent.lib", libPath);

        // KeyStore is a bootstrap class; NativeBridge must be on the bootstrap
        // classpath so it is visible from instrumented KeyStore methods.
        if (!addAgentJarToBootstrap(inst)) {
            System.err.println("[cert-agent] INSTRUMENTATION FAILURE: could not add agent JAR to "
                + "bootstrap classpath -- aborting, this JVM will NOT be monitored");
            return;
        }

        inst.addTransformer(new CertTransformer(), true /* canRetransform */);

        // Retransform KeyStore if it was already loaded before the agent attached.
        boolean retransformFailed = false;
        for (Class<?> cls : inst.getAllLoadedClasses()) {
            if ("java.security.KeyStore".equals(cls.getName())) {
                try {
                    inst.retransformClasses(cls);
                    System.out.println("[cert-agent] Retransformed java.security.KeyStore");
                } catch (Exception e) {
                    retransformFailed = true;
                    System.err.println("[cert-agent] INSTRUMENTATION FAILURE: retransform of "
                        + "java.security.KeyStore failed -- " + e.getMessage());
                }
                break;
            }
        }

        // Report a truthful status instead of an unconditional success message:
        // only claim "Initialized" if nothing observable has already failed.
        // CertTransformer.transform() can still fail later on a fresh KeyStore
        // load after this point -- that path emits its own distinct
        // "[cert-agent] INSTRUMENTATION FAILURE" line via CertTransformer
        // itself when it happens, since there's nothing more to verify here
        // synchronously.
        if (retransformFailed || CertTransformer.hasFailed()) {
            System.err.println("[cert-agent] Initialized WITH ERRORS -- certificate monitoring "
                + "for this JVM may be incomplete. Search this log for "
                + "'[cert-agent] INSTRUMENTATION FAILURE' for details.");
        } else {
            System.out.println("[cert-agent] Initialized — intercepting KeyStore.setCertificateEntry");
        }
    }

    private static String resolveLibPath(String agentArgs) {
        if (agentArgs != null && !agentArgs.trim().isEmpty()) {
            return agentArgs.trim();
        }
        // Fall back: look for libcert_agent_stub.so next to this JAR.
        try {
            URL loc = CertAgent.class.getProtectionDomain().getCodeSource().getLocation();
            File jarDir = Paths.get(loc.toURI()).getParent().toFile();
            File candidate = new File(jarDir, "libcert_agent_stub.so");
            if (candidate.exists()) return candidate.getAbsolutePath();
        } catch (Exception ignored) {}
        return null;
    }

    private static boolean addAgentJarToBootstrap(Instrumentation inst) {
        try {
            URL loc = CertAgent.class.getProtectionDomain().getCodeSource().getLocation();
            File agentJar = Paths.get(loc.toURI()).toFile();
            inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJar));
            return true;
        } catch (IOException | RuntimeException | java.net.URISyntaxException e) {
            System.err.println("[cert-agent] Could not add agent JAR to bootstrap classpath: " + e);
            return false;
        }
    }
}
