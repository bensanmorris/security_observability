package com.security.certagent;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

/**
 * Instruments java.security.KeyStore.setCertificateEntry so that every
 * explicit certificate store operation is reported to NativeBridge.
 *
 * This is the non-FIPS counterpart of the NSC_CreateObject PKCS11 hook used
 * for FIPS mode: on non-FIPS JVMs there is no NSS/libsoftokn3 intermediary,
 * so we instrument the JCA KeyStore API directly.
 *
 * Hook: KeyStore.setCertificateEntry(String alias, Certificate cert)
 *   → at entry: NativeBridge.reportCertificate(cert)
 *
 * KeyStore is a bootstrap class, so NativeBridge must also be on the
 * bootstrap classpath (CertAgent handles this via
 * Instrumentation.appendToBootstrapClassLoaderSearch).
 */
public class CertTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS  = "java/security/KeyStore";
    private static final String TARGET_METHOD = "setCertificateEntry";
    private static final String TARGET_DESC   =
            "(Ljava/lang/String;Ljava/security/cert/Certificate;)V";

    private static final String BRIDGE_CLASS  = "com/security/certagent/NativeBridge";
    private static final String BRIDGE_METHOD = "reportCertificate";
    private static final String BRIDGE_DESC   = "(Ljava/security/cert/Certificate;)V";

    // Tracked so CertAgent.setup() can report a truthful, non-misleading
    // initialization status instead of an unconditional "Initialized" that
    // doesn't reflect whether the instrumentation actually took effect.
    // transform() can be invoked again at any later point (e.g. a fresh
    // KeyStore load well after setup() returns), so this can flip to true
    // asynchronously -- CertAgent only reports what it can verify
    // synchronously at setup() time; this flag/message are the source of
    // truth for anything that happens afterward. volatile because the JVM
    // may invoke transform() from a different thread than setup() ran on.
    private static volatile boolean transformFailed = false;
    private static volatile String lastFailureReason = null;

    public static boolean hasFailed() {
        return transformFailed;
    }

    public static String getLastFailureReason() {
        return lastFailureReason;
    }

    @Override
    public byte[] transform(ClassLoader loader,
                            String className,
                            Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain,
                            byte[] classfileBuffer) {
        if (!TARGET_CLASS.equals(className)) return null;

        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            // COMPUTE_MAXS (not COMPUTE_FRAMES) avoids calling getCommonSuperClass,
            // which fails via Class.forName under the Java 11 module system when the
            // bootstrap ClassWriter cannot resolve types across named/unnamed module
            // boundaries during dynamic retransformation.  Existing stack-map frames
            // are preserved from the ClassReader; only max-stack/max-locals are
            // recomputed, which is sufficient for inserting a call at method entry.
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
            cr.accept(new KeyStoreVisitor(cw), ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            transformFailed = true;
            lastFailureReason = e.toString();
            // Distinct, consistently-greppable marker (matches CertAgent's own
            // failure lines) -- this is the only signal available when the
            // failure happens after setup() already returned, so it needs to
            // be unambiguous on its own, not just a generic warning.
            System.err.println("[cert-agent] INSTRUMENTATION FAILURE: transform of " + className
                + " failed -- certificate observations for this JVM will be incomplete: " + e);
            return null;
        }
    }

    private static class KeyStoreVisitor extends ClassVisitor {
        KeyStoreVisitor(ClassWriter cw) {
            super(Opcodes.ASM9, cw);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (TARGET_METHOD.equals(name) && TARGET_DESC.equals(descriptor)) {
                return new SetCertEntryAdvisor(mv, access, name, descriptor);
            }
            return mv;
        }
    }

    private static class SetCertEntryAdvisor extends AdviceAdapter {

        SetCertEntryAdvisor(MethodVisitor mv, int access, String name, String desc) {
            super(Opcodes.ASM9, mv, access, name, desc);
        }

        @Override
        protected void onMethodEnter() {
            // Signature: setCertificateEntry(String alias, Certificate cert)
            // AdviceAdapter.loadArg is 0-based, excluding 'this':
            //   loadArg(0) = alias, loadArg(1) = cert
            loadArg(1);
            invokeStatic(
                Type.getObjectType(BRIDGE_CLASS),
                new Method(BRIDGE_METHOD, BRIDGE_DESC)
            );
        }
    }
}
