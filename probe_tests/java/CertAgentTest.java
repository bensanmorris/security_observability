/*
 * CertAgentTest.java
 *
 * Long-running test target for the cert-agent dynamic attach workflow.
 *
 * Prints its PID, then loops every INTERVAL_MS milliseconds calling
 * KeyStore.setCertificateEntry() on an in-memory keystore.  Once the
 * cert-agent is attached via jattach, each loop iteration fires a
 * java_cert_agent_write uprobe event that cert_analyzer picks up via
 * _handle_uprobe_in_memory_cert — the same path as SSL_CTX_use_certificate_ASN1.
 *
 * Usage:
 *   # Terminal 1 — start the target JVM
 *   java -cp . CertAgentTest [cert.pem] [interval_ms]
 *
 *   # Terminal 2 — attach the agent once the PID is printed
 *   ./cert-agent/jattach-linux-x64/jattach <pid> load instrument false \
 *       /opt/cert-agent/cert-agent.jar=/opt/cert-agent/libcert_agent_stub.so
 *
 * Arguments:
 *   cert.pem     Certificate to import on each loop (default: ../../test-certs/valid.crt)
 *   interval_ms  Milliseconds between iterations              (default: 5000)
 *
 * Exits cleanly on Ctrl+C or SIGTERM.
 */

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;

public class CertAgentTest {

    public static void main(String[] args) throws Exception {
        String certPath   = "test-certs/valid.crt";
        long   intervalMs = 5_000;

        for (String a : args) {
            if (a.matches("\\d+")) {
                intervalMs = Long.parseLong(a);
            } else if (!a.startsWith("--")) {
                certPath = a;
            }
        }

        System.out.println("=== CertAgentTest ===");
        System.out.printf("PID      : %d%n", ProcessHandle.current().pid());
        System.out.printf("cert     : %s%n", certPath);
        System.out.printf("interval : %d ms%n", intervalMs);
        System.out.println();
        System.out.println("Attach the cert-agent now, then watch cert_analyzer for events.");
        System.out.println("Ctrl+C to exit.");
        System.out.println();

        X509Certificate cert = loadCert(certPath);
        System.out.printf("Loaded   : %s%n", cert.getSubjectX500Principal());
        System.out.println();

        Runtime.getRuntime().addShutdownHook(new Thread(() ->
            System.out.println("\nShutdown — exiting.")
        ));

        int iteration = 0;
        while (!Thread.currentThread().isInterrupted()) {
            iteration++;

            // Fresh in-memory KeyStore each time — no persistence needed,
            // we just want setCertificateEntry() to fire the uprobe.
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null, null);
            ks.setCertificateEntry("test-cert", cert);

            System.out.printf("[%d] KeyStore.setCertificateEntry fired — serial %s%n",
                iteration, cert.getSerialNumber().toString(16));

            try {
                Thread.sleep(intervalMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static X509Certificate loadCert(String path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = new FileInputStream(path)) {
            return (X509Certificate) cf.generateCertificate(in);
        }
    }
}
