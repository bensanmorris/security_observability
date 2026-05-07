# probe_tests

CMake-based programs that exercise the Tetragon uprobe hooks defined in
`tetragon-policies/experimental/`. Run these with Tetragon active to confirm
that `cert_analyzer.py` receives the expected events.

## Build

```bash
sudo dnf install cmake   # if not already installed
mkdir build && cd build
cmake ..
make
```

## Tests

### test_openssl3_cert_load

Exercises the three uprobe hooks in `openssl3-cert-load.yaml`.

```bash
./test_openssl3_cert_load                        # uses ../test-certs/valid.crt
./test_openssl3_cert_load /path/to/other.crt
```

| # | Function | Uprobe hook captures |
|---|----------|----------------------|
| 1 | `SSL_CTX_use_certificate_file` | `args[1]` = file path as `string_arg` |
| 2 | `SSL_CTX_use_certificate_chain_file` | `args[1]` = file path as `string_arg` |
| 3 | `SSL_CTX_use_certificate_ASN1` | `args[1]` = DER length, `args[2]` = raw DER bytes as `char_buf` → handled by `cert_analyzer._handle_uprobe_in_memory_cert` |
