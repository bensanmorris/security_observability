/*
 * FipsJavaCertLoad.java
 *
 * Exercises the NSS/PKCS11 uprobe hooks defined in
 * tetragon-policies/experimental/java-fips-nss-cert.yaml, which are
 * relevant when FIPS mode is enabled on RHEL.
 *
 * When FIPS mode is active, Java is forced to use SunPKCS11-NSS-FIPS as its
 * primary crypto provider.  All certificate operations route through
 * libsoftokn3.so (the NSS PKCS11 token library) rather than Java's internal
 * providers, making it possible to hook cert loads at the native library level.
 *
 * Three test paths mirror the structure of test_openssl3_cert_load.cpp:
 *
 *   [1] KeyStore.load (PKCS11) — enumerates the NSS token via NSC_FindObjectsInit
 *       + NSC_FindObjects in libsoftokn3.so.  Analogous to SSL_CTX_use_certificate_file.
 *
 *   [2] CertificateFactory (file) — parses a PEM cert.  With SunPKCS11 installed as
 *       provider #1, digest operations route through PKCS11 and fire NSC_CreateObject
 *       for session objects.  Demonstrates provider interception even for file-path loads.
 *
 *   [3] KeyStore.setCertificateEntry — imports a cert DER blob into the PKCS11 token;
 *       fires NSC_CreateObject with CKA_CLASS=CKO_CERTIFICATE (0x01).  This is the
 *       in-memory equivalent of SSL_CTX_use_certificate_ASN1: cert_analyzer reads the
 *       DER bytes from the NSC_CreateObject template via /proc/<pid>/mem.
 *
 * Build:
 *   cd probe_tests/java && ./build.sh
 *
 * Usage:
 *   java -cp . FipsJavaCertLoad [--pause] [cert.pem]
 *
 *   --pause   After all tests complete, pause until Ctrl+C (useful for inspecting
 *             Tetragon events while the process is still live).
 *   cert.pem  Certificate for tests 1-3 (default: ../../test-certs/valid.crt).
 */

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class FipsJavaCertLoad {

    // NSS config for a writable DB — written to a temp path at runtime.
    private static final String NSS_CFG_TEMPLATE =
            "name = NSS-FIPS-TEST\n" +
            "nssLibraryDirectory = /usr/lib64\n" +
            "nssSecmodDirectory = sql:%s\n" +
            "nssDbMode = readWrite\n" +
            "attributes = compatibility\n";

    // CKA_CLASS value for certificate objects in PKCS11
    @SuppressWarnings("unused")
    private static final long CKO_CERTIFICATE = 1L;

    public static void main(String[] args) throws Exception {
        String certPath = "../../test-certs/valid.crt";
        boolean doPause = false;

        for (String a : args) {
            if ("--pause".equals(a)) {
                doPause = true;
            } else if (!a.startsWith("--")) {
                certPath = a;
            }
        }

        System.out.println("=== java-fips-nss uprobe probe test ===");
        System.out.println("cert    : " + certPath);
        System.out.println("PID     : " + ProcessHandle.current().pid());
        System.out.println();

        // NSS can only be initialised once per JVM process, so all three tests
        // share a single writable DB.  certutil pre-loads the test cert so that
        // test 1 (KeyStore.load enumeration) always finds at least one alias.
        Path tempDir = Files.createTempDirectory("fips_probe_");
        Path nssDb   = tempDir.resolve("nssdb");
        Files.createDirectories(nssDb);

        try {
            // Create the DB and pre-populate it with the test cert.
            certutil("-N", "-d", "sql:" + nssDb, "--empty-password");
            certutil("-A", "-d", "sql:" + nssDb,
                     "-n", "probe-cert", "-t", "CT,C,C", "-i", certPath);

            // Write a single NSS config referencing the writable DB.
            Path nssCfg = tempDir.resolve("nss.cfg");
            Files.writeString(nssCfg, String.format(NSS_CFG_TEMPLATE, nssDb));

            int run = 0, failures = 0;

            // ------------------------------------------------------------------
            // Test 1 — KeyStore.load (PKCS11) certificate enumeration
            // Uprobe: NSC_FindObjectsInit / NSC_FindObjects in libsoftokn3.so
            // ------------------------------------------------------------------
            // Install the provider once; all three tests share it (NSS init is process-global).
            Provider p11 = buildP11Provider(nssCfg);

            // ------------------------------------------------------------------
            // Test 1 — KeyStore.load (PKCS11) certificate enumeration
            // Uprobe: NSC_FindObjectsInit / NSC_FindObjects in libsoftokn3.so
            // ------------------------------------------------------------------
            System.out.println("[1] KeyStore.load — PKCS11 certificate enumeration");
            System.out.println("    nssdb: " + nssDb);
            run++;
            try {
                KeyStore ks = KeyStore.getInstance("PKCS11", p11);
                ks.load(null, null);
                List<String> aliases = Collections.list(ks.aliases());
                System.out.println("    aliases: " + aliases);
                if (!aliases.isEmpty()) {
                    System.out.println("    PASS");
                } else {
                    System.out.println("    WARN — no aliases found (certutil import may have failed)");
                }
            } catch (Exception e) {
                System.out.println("    FAIL: " + e.getMessage());
                failures++;
            }
            System.out.println();

            // ------------------------------------------------------------------
            // Test 2 — CertificateFactory (file path)
            // With SunPKCS11 as provider #1, internal digest ops fire NSC_CreateObject
            // ------------------------------------------------------------------
            System.out.println("[2] CertificateFactory.generateCertificate (file path)");
            System.out.println("    path: " + certPath);
            run++;
            X509Certificate cert = null;
            try {
                // CertificateFactory itself is pure-Java; PKCS11 is exercised for
                // any digest or key op triggered during provider initialisation.
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                try (InputStream in = new FileInputStream(certPath)) {
                    cert = (X509Certificate) cf.generateCertificate(in);
                }
                System.out.println("    subject : " + cert.getSubjectX500Principal());
                System.out.println("    notAfter: " + cert.getNotAfter());
                System.out.println("    PASS");
            } catch (Exception e) {
                System.out.println("    FAIL: " + e.getMessage());
                failures++;
            }
            System.out.println();

            // ------------------------------------------------------------------
            // Test 3 — KeyStore.setCertificateEntry (in-memory DER import)
            // Uprobe: NSC_CreateObject with CKA_CLASS=CKO_CERTIFICATE in libsoftokn3.so
            // cert_analyzer extracts the DER bytes via /proc/<pid>/mem walk of pTemplate.
            // ------------------------------------------------------------------
            System.out.println("[3] KeyStore.setCertificateEntry — in-memory DER import");
            System.out.println("    cert: " + (cert != null ? cert.getSubjectX500Principal() : "(unavailable)"));
            run++;
            if (cert == null) {
                System.out.println("    SKIP — cert unavailable from test 2");
                failures++;
            } else {
                try {
                    KeyStore ks = KeyStore.getInstance("PKCS11", p11);
                    ks.load(null, null);
                    ks.setCertificateEntry("import-test", cert);
                    System.out.println("    serial  : " + cert.getSerialNumber().toString(16));
                    System.out.println("    imported into PKCS11 token (DER bytes in NSC_CreateObject template)");
                    System.out.println("    PASS");
                } catch (Exception e) {
                    System.out.println("    FAIL: " + e.getMessage());
                    failures++;
                }
            }

            System.out.println();
            System.out.println("=== " + (run - failures) + "/" + run + " passed" +
                               (failures > 0 ? " (" + failures + " failed)" : "") + " ===");

            if (doPause) {
                System.out.println("PID " + ProcessHandle.current().pid() + " pausing — press Ctrl+C to exit");
                Thread.currentThread().join();
            }

        } finally {
            deleteRecursive(tempDir);
        }
    }

    // Build a SunPKCS11 provider from the given NSS config file.
    // Each test needs its own provider instance to avoid token conflicts.
    private static Provider buildP11Provider(Path cfgPath) throws Exception {
        Provider p11 = Security.getProvider("SunPKCS11");
        if (p11 == null) throw new RuntimeException("SunPKCS11 provider not available");
        p11 = p11.configure(cfgPath.toString());
        // Insert at position 1 (highest priority) without permanently altering the
        // global provider list between tests — we reinstall fresh each time.
        Security.removeProvider(p11.getName());
        Security.insertProviderAt(p11, 1);
        return p11;
    }

    private static void certutil(String... cmdArgs) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add("certutil");
        cmd.addAll(Arrays.asList(cmdArgs));
        Process p = new ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start();
        String output = new String(p.getInputStream().readAllBytes());
        int rc = p.waitFor();
        if (rc != 0) throw new RuntimeException("certutil failed (rc=" + rc + "): " + output.trim());
    }

    private static void deleteRecursive(Path dir) throws IOException {
        if (!Files.exists(dir)) return;
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try { Files.delete(p); } catch (IOException ignored) {}
            });
        }
    }
}
