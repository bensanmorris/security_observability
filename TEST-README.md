# Certificate Analyzer Test Suite

Comprehensive pytest-based test suite for the TLS Certificate Expiry Monitor with multi-certificate support.

## Test Coverage

### Test Classes

1. **TestCertificateGeneration**
   - Helper class for generating test certificates
   - Supports PEM, DER, single and multi-cert bundles

2. **TestSingleCertificateParsing**
   - PEM certificate parsing
   - DER certificate parsing
   - Nonexistent file handling
   - Invalid certificate handling

3. **TestMultiCertificateParsing**
   - Multi-certificate bundle parsing
   - Empty bundle handling
   - Mixed content (certs + keys) handling

4. **TestCertificateAnalysis**
   - Valid certificate analysis
   - Expired certificate detection
   - Expiring soon detection
   - Multi-certificate bundle analysis
   - Certificate indexing

5. **TestCertificateInfo**
   - Unique key generation
   - Expiry threshold testing
   - Dataclass functionality

6. **TestPathDetection**
   - Valid extension detection (.pem, .crt, .cert, .cer, .key)
   - Invalid extension rejection
   - Case insensitivity

7. **TestMetrics**
   - Prometheus metrics updates for single certificates
   - Prometheus metrics updates for multi-certificate bundles

8. **TestEdgeCases**
   - Certificates without common names
   - Permission denied scenarios
   - Corrupted PEM data in bundles

9. **TestCABundles**
   - Root CA + Intermediate CA + Leaf certificate chains
   - Expired intermediate certificate detection

## Installation

```bash
# Install test dependencies
pip install -r test-requirements.txt
```

## Running Tests

### Run all tests
```bash
pytest test_cert_analyzer.py -v
```

### Run with coverage
```bash
pytest test_cert_analyzer.py --cov=cert_analyzer_multi --cov-report=html -v
```

### Run specific test class
```bash
pytest test_cert_analyzer.py::TestMultiCertificateParsing -v
```

### Run specific test
```bash
pytest test_cert_analyzer.py::TestMultiCertificateParsing::test_parse_multi_certificate_bundle -v
```

### Run with detailed output
```bash
pytest test_cert_analyzer.py -vv -s
```

## Test Scenarios

### Single Certificate Tests
- ✅ Parse single PEM certificate
- ✅ Parse single DER certificate
- ✅ Handle nonexistent files
- ✅ Handle invalid certificate data

### Multi-Certificate Bundle Tests
- ✅ Parse bundle with 3 certificates
- ✅ Handle empty bundles
- ✅ Parse bundles with mixed content (certs + keys)
- ✅ Handle corrupted certificates in bundles

### Certificate Analysis Tests
- ✅ Analyze valid certificates (365 days)
- ✅ Detect expired certificates (-10 days)
- ✅ Detect expiring soon (5 days)
- ✅ Analyze multi-certificate bundles
- ✅ Verify certificate indexing (0, 1, 2...)
- ✅ Verify unique key generation

### Real-World Scenarios
- ✅ CA bundle with Root + Intermediate + Leaf
- ✅ Detect expired intermediate CA in chain
- ✅ Certificates without common names
- ✅ Permission denied file access

## Expected Output

```
test_cert_analyzer.py::TestSingleCertificateParsing::test_parse_single_pem_certificate PASSED
test_cert_analyzer.py::TestSingleCertificateParsing::test_parse_single_der_certificate PASSED
test_cert_analyzer.py::TestMultiCertificateParsing::test_parse_multi_certificate_bundle PASSED
test_cert_analyzer.py::TestCertificateAnalysis::test_analyze_multi_certificate_bundle PASSED
test_cert_analyzer.py::TestCABundles::test_expired_intermediate_in_chain PASSED
...

========================= 30 passed in 2.5s =========================
```

## Coverage Goals

Target coverage: **>90%**

Key areas:
- Certificate parsing (PEM, DER, multi-cert)
- Error handling (file not found, permission denied, corrupted data)
- Certificate analysis (valid, expired, expiring soon)
- Metrics updates
- Edge cases

## Continuous Integration

Add to your CI pipeline:

```yaml
# GitHub Actions example
- name: Run tests
  run: |
    pip install -r test-requirements.txt
    pytest test_cert_analyzer.py --cov=cert_analyzer_multi --cov-report=xml
    
- name: Upload coverage
  uses: codecov/codecov-action@v3
```

## Test Data

All test certificates are generated dynamically using the `cryptography` library.
No static certificate files are required.

Test certificates include:
- Valid certificates (365 days)
- Expired certificates (-10 days)
- Expiring soon (5, 7 days)
- Long-lived CA certificates (3650 days)
- Certificates with and without common names
- Certificate chains (Root → Intermediate → Leaf)

## Troubleshooting

### Import errors
```bash
# Make sure cert_analyzer_multi.py is in the same directory
# or adjust the import path in the test file
```

### Permission errors on temp files
```bash
# Tests clean up automatically, but if interrupted:
chmod -R 755 /tmp/pytest-*
rm -rf /tmp/pytest-*
```

## Contributing

When adding new features to cert_analyzer_multi.py:
1. Add corresponding tests
2. Run full test suite
3. Verify coverage remains >90%
4. Update this README with new test scenarios
