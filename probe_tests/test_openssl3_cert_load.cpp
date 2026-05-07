/*
 * test_openssl3_cert_load.cpp
 *
 * Exercises the three uprobe hooks defined in
 * tetragon-policies/experimental/openssl3-cert-load.yaml:
 *
 *   1. SSL_CTX_use_certificate_file      (file path, PEM or DER)
 *   2. SSL_CTX_use_certificate_chain_file (file path, PEM chain)
 *   3. SSL_CTX_use_certificate_ASN1      (raw DER bytes in memory)
 *
 * Usage: ./test_openssl3_cert_load [cert.pem]
 *
 * Defaults to ../test-certs/valid.crt when no argument is supplied so the
 * binary can be run directly from a build/ subdirectory of probe_tests/.
 *
 * Each test creates a fresh SSL_CTX, invokes the target function, then
 * frees the context. This matches how real applications use the API and
 * ensures Tetragon captures distinct uprobe events for each call.
 *
 * Build:
 *   mkdir build && cd build
 *   cmake ..
 *   make
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void print_ssl_errors(const std::string& context)
{
    unsigned long err;
    while ((err = ERR_get_error())) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "  SSL error [" << context << "]: " << buf << "\n";
    }
}

static SSL_CTX* make_ctx()
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "  Failed to create SSL_CTX\n";
        print_ssl_errors("SSL_CTX_new");
    }
    return ctx;
}

// ---------------------------------------------------------------------------
// Test 1 — SSL_CTX_use_certificate_file
//
// Uprobe hook: args[0]=SSL_CTX*, args[1]=char* (file path)
// Tetragon captures args[1] as a string_arg → cert_analyzer sees the path.
// ---------------------------------------------------------------------------
static bool test_use_certificate_file(const std::string& cert_path)
{
    std::cout << "[1] SSL_CTX_use_certificate_file\n"
              << "    path: " << cert_path << "\n";

    SSL_CTX* ctx = make_ctx();
    if (!ctx) return false;

    int rc = SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_free(ctx);

    if (rc != 1) {
        std::cerr << "  FAIL (rc=" << rc << ")\n";
        print_ssl_errors("SSL_CTX_use_certificate_file");
        return false;
    }
    std::cout << "    PASS\n";
    return true;
}

// ---------------------------------------------------------------------------
// Test 2 — SSL_CTX_use_certificate_chain_file
//
// Uprobe hook: args[0]=SSL_CTX*, args[1]=char* (file path)
// Same shape as use_certificate_file; exercises the second symbol in the
// policy so both hooks are confirmed live.
// ---------------------------------------------------------------------------
static bool test_use_certificate_chain_file(const std::string& cert_path)
{
    std::cout << "[2] SSL_CTX_use_certificate_chain_file\n"
              << "    path: " << cert_path << "\n";

    SSL_CTX* ctx = make_ctx();
    if (!ctx) return false;

    int rc = SSL_CTX_use_certificate_chain_file(ctx, cert_path.c_str());
    SSL_CTX_free(ctx);

    if (rc != 1) {
        std::cerr << "  FAIL (rc=" << rc << ")\n";
        print_ssl_errors("SSL_CTX_use_certificate_chain_file");
        return false;
    }
    std::cout << "    PASS\n";
    return true;
}

// ---------------------------------------------------------------------------
// Test 3 — SSL_CTX_use_certificate_ASN1
//
// Uprobe hook: args[0]=SSL_CTX*, args[1]=int (len), args[2]=char_buf (DER)
// Tetragon reads the DER bytes via bpf_probe_read_user at hook entry using
// args[1] as the buffer length (sizeArgIndex: 2 in the policy).
// cert_analyzer receives a bytes_arg and parses it with load_der_x509_certificate.
//
// Steps:
//   a. Read the PEM file and decode the first certificate.
//   b. Re-encode to DER with i2d_X509 — this is the raw bytes the uprobe captures.
//   c. Call SSL_CTX_use_certificate_ASN1 with those bytes.
// ---------------------------------------------------------------------------
static bool test_use_certificate_asn1(const std::string& cert_path)
{
    std::cout << "[3] SSL_CTX_use_certificate_ASN1 (in-memory DER)\n"
              << "    source: " << cert_path << "\n";

    // --- a. Load PEM ---
    FILE* f = fopen(cert_path.c_str(), "r");
    if (!f) {
        std::cerr << "  FAIL: cannot open " << cert_path << "\n";
        return false;
    }
    X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!cert) {
        std::cerr << "  FAIL: PEM_read_X509\n";
        print_ssl_errors("PEM_read_X509");
        return false;
    }

    // --- b. Encode to DER ---
    unsigned char* der_buf = nullptr;
    int der_len = i2d_X509(cert, &der_buf);
    X509_free(cert);
    if (der_len <= 0 || !der_buf) {
        std::cerr << "  FAIL: i2d_X509 (der_len=" << der_len << ")\n";
        print_ssl_errors("i2d_X509");
        return false;
    }
    std::cout << "    DER length: " << der_len << " bytes\n";

    // --- c. Load via ASN1 ---
    SSL_CTX* ctx = make_ctx();
    if (!ctx) {
        OPENSSL_free(der_buf);
        return false;
    }

    int rc = SSL_CTX_use_certificate_ASN1(ctx, der_len, der_buf);
    OPENSSL_free(der_buf);
    SSL_CTX_free(ctx);

    if (rc != 1) {
        std::cerr << "  FAIL (rc=" << rc << ")\n";
        print_ssl_errors("SSL_CTX_use_certificate_ASN1");
        return false;
    }
    std::cout << "    PASS\n";
    return true;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    const std::string cert_path = (argc > 1) ? argv[1] : "../test-certs/valid.crt";

    OPENSSL_init_ssl(
        OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS,
        nullptr);

    std::cout << "=== openssl3-cert-load uprobe probe test ===\n"
              << "cert: " << cert_path << "\n\n";

    int failures = 0;
    if (!test_use_certificate_file(cert_path))       ++failures;
    std::cout << "\n";
    if (!test_use_certificate_chain_file(cert_path)) ++failures;
    std::cout << "\n";
    if (!test_use_certificate_asn1(cert_path))       ++failures;

    std::cout << "\n=== " << (3 - failures) << "/3 passed";
    if (failures)
        std::cout << " (" << failures << " failed)";
    std::cout << " ===\n";

    return failures ? 1 : 0;
}
