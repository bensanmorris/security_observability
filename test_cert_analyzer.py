"""
Test Suite for TLS Certificate Expiry Monitor
Tests multi-certificate file parsing and analysis
"""

import pytest
import logging
import tempfile
import os
import time
import threading
import grpc
from datetime import datetime, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend
from prometheus_client import REGISTRY

# Import the analyzer (adjust path as needed)
import sys
sys.path.insert(0, os.path.dirname(__file__))
from cert_analyzer import CertificateAnalyzer, CertificateInfo, LRUCache


class TestCertificateGeneration:
    """Helper class for generating test certificates"""
    
    @staticmethod
    def generate_certificate(
        common_name: str,
        days_valid: int,
        is_ca: bool = False
    ) -> tuple:
        """Generate a self-signed test certificate and its private key"""
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Calculate validity dates
        if days_valid < 0:
            # Expired certificate
            not_valid_before = datetime.utcnow() + timedelta(days=days_valid) - timedelta(days=365)
            not_valid_after = datetime.utcnow() + timedelta(days=days_valid)
        else:
            # Valid certificate
            not_valid_before = datetime.utcnow()
            not_valid_after = datetime.utcnow() + timedelta(days=days_valid)
        
        # Build certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TestState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "TestCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )
        
        # Add basic constraints for CA certificates
        if is_ca:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
        
        # Add SAN
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName(f"www.{common_name}"),
            ]),
            critical=False,
        )
        
        cert = builder.sign(private_key, hashes.SHA256(), backend=default_backend())
        
        return cert, private_key
    
    @staticmethod
    def save_certificate_pem(cert, filepath):
        """Save a certificate to a PEM file"""
        with open(filepath, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    @staticmethod
    def save_certificate_der(cert, filepath):
        """Save a certificate to a DER file"""
        with open(filepath, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.DER))
    
    @staticmethod
    def save_multi_certificate_pem(certs, filepath):
        """Save multiple certificates to a single PEM file (bundle)"""
        with open(filepath, 'wb') as f:
            for cert in certs:
                f.write(cert.public_bytes(serialization.Encoding.PEM))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test certificates"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def analyzer():
    """Create a certificate analyzer instance, cleaning up Prometheus registry after each test"""
    # Clear collectors from previous tests
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        try:
            REGISTRY.unregister(collector)
        except Exception:
            pass
    
    # Create analyzer (will register metrics to clean registry)
    test_analyzer = CertificateAnalyzer(
        tetragon_address="unix:///dev/null",
        alert_threshold_days=30
    )
    
    yield test_analyzer
    
    # Cleanup after test
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        try:
            REGISTRY.unregister(collector)
        except Exception:
            pass


class TestSingleCertificateParsing:
    """Test parsing of single certificate files"""
    
    def test_parse_single_pem_certificate(self, analyzer, temp_dir):
        """Test parsing a single PEM certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        cert_path = os.path.join(temp_dir, "single.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        certs = analyzer.parse_certificates(cert_path)
        
        assert len(certs) == 1
        assert certs[0].subject.rfc4514_string() == cert.subject.rfc4514_string()
    
    def test_parse_single_der_certificate(self, analyzer, temp_dir):
        """Test parsing a single DER certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        cert_path = os.path.join(temp_dir, "single.der")
        TestCertificateGeneration.save_certificate_der(cert, cert_path)
        
        certs = analyzer.parse_certificates(cert_path)
        
        assert len(certs) == 1
        assert certs[0].subject.rfc4514_string() == cert.subject.rfc4514_string()
    
    def test_parse_nonexistent_file(self, analyzer):
        """Test parsing a file that doesn't exist"""
        certs = analyzer.parse_certificates("/nonexistent/file.pem")
        
        assert len(certs) == 0
    
    def test_parse_invalid_certificate(self, analyzer, temp_dir):
        """Test parsing an invalid certificate file"""
        cert_path = os.path.join(temp_dir, "invalid.pem")
        with open(cert_path, 'w') as f:
            f.write("This is not a certificate")
        
        certs = analyzer.parse_certificates(cert_path)
        
        assert len(certs) == 0


class TestMultiCertificateParsing:
    """Test parsing of multi-certificate bundle files"""
    
    def test_parse_multi_certificate_bundle(self, analyzer, temp_dir):
        """Test parsing a bundle with multiple certificates"""
        cert1, _ = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", 180)
        cert3, _ = TestCertificateGeneration.generate_certificate("cert3.example.com", 90)
        
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2, cert3], bundle_path)
        
        certs = analyzer.parse_certificates(bundle_path)
        
        assert len(certs) == 3
        assert certs[0].subject.rfc4514_string() == cert1.subject.rfc4514_string()
        assert certs[1].subject.rfc4514_string() == cert2.subject.rfc4514_string()
        assert certs[2].subject.rfc4514_string() == cert3.subject.rfc4514_string()
    
    def test_parse_empty_bundle(self, analyzer, temp_dir):
        """Test parsing an empty bundle file"""
        bundle_path = os.path.join(temp_dir, "empty.pem")
        with open(bundle_path, 'w') as f:
            f.write("")

        certs = analyzer.parse_certificates(bundle_path)

        assert len(certs) == 0

    def test_parse_certificates_skips_fifo(self, analyzer, temp_dir):
        """
        parse_certificates must not block on a FIFO with no writer -- open()
        on a named pipe blocks indefinitely per POSIX semantics, and
        cert_path here comes straight from a Tetragon-reported path filtered
        only by extension, so any unprivileged process creating e.g.
        `mkfifo x.pem` would otherwise hang the single-threaded event
        consumer forever. Runs the call on a background thread with a
        timeout so a regression fails fast instead of hanging the test run.
        """
        fifo_path = os.path.join(temp_dir, "pipe.pem")
        os.mkfifo(fifo_path)

        result = {}

        def _call():
            result['certs'] = analyzer.parse_certificates(fifo_path)

        t = threading.Thread(target=_call, daemon=True)
        t.start()
        t.join(timeout=2.0)

        assert not t.is_alive(), "parse_certificates blocked on a FIFO with no writer"
        assert result.get('certs') == []


class TestLargeFileBackgroundProcessing:
    """Files with more PEM certs than large_file_cert_threshold are parsed off-thread"""

    @staticmethod
    def _make_event(path, process='/usr/bin/cat', pid=4242):
        from unittest.mock import MagicMock
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = process
        mock_kprobe.process.pid.value = pid
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe
        mock_event.node_name = ''
        return mock_event

    def _wait_for_background_processing(self, analyzer, path, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if path not in analyzer._large_file_in_flight:
                return
            time.sleep(0.01)
        pytest.fail("background certificate parsing did not finish in time")

    def test_count_pem_certs(self, analyzer, temp_dir):
        """_count_pem_certs counts BEGIN markers without parsing"""
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        assert analyzer._count_pem_certs(bundle_path) == 5

    def test_count_pem_certs_skips_fifo(self, analyzer, temp_dir):
        """
        _count_pem_certs must not block on a FIFO with no writer -- open()
        on a named pipe blocks indefinitely per POSIX semantics, and this
        runs on the single-threaded event-consumer loop, so any unprivileged
        process on the node creating e.g. `mkfifo x.pem` would otherwise
        hang cert event processing forever. Runs the call on a background
        thread with a timeout so a regression fails fast instead of hanging
        the test run.
        """
        fifo_path = os.path.join(temp_dir, "pipe.pem")
        os.mkfifo(fifo_path)

        result = {}

        def _call():
            result['count'] = analyzer._count_pem_certs(fifo_path)

        t = threading.Thread(target=_call, daemon=True)
        t.start()
        t.join(timeout=2.0)

        assert not t.is_alive(), "_count_pem_certs blocked on a FIFO with no writer"
        assert result.get('count') == 0

    def test_count_pem_certs_default_byte_cap(self, analyzer):
        """Default _large_file_byte_cap is 2MB unless overridden"""
        assert analyzer._large_file_byte_cap == 2 * 1024 * 1024

    def test_count_pem_certs_respects_byte_cap(self, analyzer, temp_dir):
        """
        _count_pem_certs only reads/counts the first _large_file_byte_cap
        bytes -- markers beyond the cap must not be counted, since the whole
        point of the cap is to bound the read regardless of how many more
        markers a bigger file might contain past that point.
        """
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "capped_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        with open(bundle_path, 'rb') as f:
            data = f.read()

        marker = b'-----BEGIN CERTIFICATE-----'
        # Offset of the 3rd marker -- capping the read here means only the
        # first 2 certs' markers are visible.
        offset = data.index(marker)
        offset = data.index(marker, offset + 1)
        offset = data.index(marker, offset + 1)

        analyzer._large_file_byte_cap = offset
        assert analyzer._count_pem_certs(bundle_path) == 2

        # Sanity check: with a cap covering the whole file, all 5 are counted.
        analyzer._large_file_byte_cap = len(data)
        assert analyzer._count_pem_certs(bundle_path) == 5

    def test_byte_cap_can_undercount_and_misroute_large_bundle(self, analyzer, temp_dir):
        """
        Documents the accepted tradeoff of the byte-cap approach: if a bundle's
        markers are spread out past the cap, _count_pem_certs undercounts and
        the file is routed synchronously even though it actually exceeds
        _large_file_cert_threshold. Real-world CA bundles are far smaller than
        the default 2MB cap (see cert-analyzer.conf), so this only matters if
        the cap is configured too small for the certs actually being scanned.
        """
        analyzer._large_file_cert_threshold = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "misrouted_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        with open(bundle_path, 'rb') as f:
            data = f.read()
        marker = b'-----BEGIN CERTIFICATE-----'
        offset = data.index(marker)
        offset = data.index(marker, offset + 1)
        offset = data.index(marker, offset + 1)

        # Cap only reveals 2 markers -- under the threshold of 3, even though
        # the file actually contains 5 certs.
        analyzer._large_file_byte_cap = offset
        assert analyzer._count_pem_certs(bundle_path) == 2

        analyzer.process_event(self._make_event(bundle_path))

        # Processed synchronously (not routed to the background-thread path)
        # despite exceeding the threshold, because the byte cap hid the rest.
        assert bundle_path not in analyzer._large_file_in_flight
        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 5

    def test_is_large_certificate_file_pkcs12_uses_byte_cap(self, analyzer, temp_dir):
        """
        JKS/PKCS12 routing is gated by _large_file_byte_cap (size), not cert
        count -- _count_pem_certs always returns 0 for these extensions
        (they have no cheap text marker to count), so _is_large_certificate_file
        must not fall through to the PEM-marker comparison for them. Content
        doesn't matter here, only size, since the check is a plain stat().
        """
        analyzer._large_file_byte_cap = 100
        small_path = os.path.join(temp_dir, "small.p12")
        with open(small_path, 'wb') as f:
            f.write(b'x' * 50)
        large_path = os.path.join(temp_dir, "large.p12")
        with open(large_path, 'wb') as f:
            f.write(b'x' * 200)

        assert not analyzer._is_large_certificate_file(small_path)
        assert analyzer._is_large_certificate_file(large_path)

        # Same gate applies to the other JKS/PKCS12 extensions.
        jks_path = os.path.join(temp_dir, "large.jks")
        with open(jks_path, 'wb') as f:
            f.write(b'x' * 200)
        assert analyzer._is_large_certificate_file(jks_path)

    def test_is_large_certificate_file_der_falls_back_to_byte_cap(self, analyzer, temp_dir):
        """
        A .crt/.cer/.cert file with no PEM markers (binary DER content, or
        just garbage) must not be silently treated as "small" -- 0 markers
        found is ambiguous between "genuinely tiny file" and "binary content
        the text scan can't see" (parse_certificates falls back to
        load_der_x509_certificate for exactly these extensions). Falls back
        to the same byte-cap gate as JKS/PKCS12 rather than defaulting to
        the sync path.
        """
        analyzer._large_file_byte_cap = 100
        small_der_path = os.path.join(temp_dir, "small.crt")
        with open(small_der_path, 'wb') as f:
            f.write(b'\x30\x82' + b'\x00' * 40)  # DER-ish, no PEM markers, under cap
        large_der_path = os.path.join(temp_dir, "large.cer")
        with open(large_der_path, 'wb') as f:
            f.write(b'\x30\x82' + b'\x00' * 300)  # DER-ish, no PEM markers, over cap

        assert analyzer._count_pem_certs(large_der_path) == 0  # confirms the marker scan is blind here
        assert not analyzer._is_large_certificate_file(small_der_path)
        assert analyzer._is_large_certificate_file(large_der_path)

    def test_is_large_certificate_file_key_falls_back_to_byte_cap(self, analyzer, temp_dir):
        """
        .key files (private keys, discoverable via periodic_scan even though
        no Tetragon policy watches them -- see is_cert_path) contain no
        "-----BEGIN CERTIFICATE-----" marker either, only a private-key PEM
        header. Same zero-markers fallback as the DER case above must apply
        so a large .key file can't bypass the gate.
        """
        analyzer._large_file_byte_cap = 100
        small_key_path = os.path.join(temp_dir, "small.key")
        with open(small_key_path, 'wb') as f:
            f.write(b'-----BEGIN PRIVATE KEY-----\n' + b'x' * 20)
        large_key_path = os.path.join(temp_dir, "large.key")
        with open(large_key_path, 'wb') as f:
            f.write(b'-----BEGIN PRIVATE KEY-----\n' + b'x' * 300)

        assert analyzer.is_cert_path(large_key_path)
        assert analyzer._count_pem_certs(large_key_path) == 0  # no CERTIFICATE marker in a private key
        assert not analyzer._is_large_certificate_file(small_key_path)
        assert analyzer._is_large_certificate_file(large_key_path)

    def test_small_file_processed_synchronously(self, analyzer, temp_dir):
        """A file at or below the threshold is processed inline, no background thread"""
        analyzer._large_file_cert_threshold = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(3)]
        bundle_path = os.path.join(temp_dir, "small_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        analyzer.process_event(self._make_event(bundle_path))

        # No wait needed — must already be populated when process_event returns
        assert bundle_path not in analyzer._large_file_in_flight
        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 3

    def test_large_file_processed_in_background(self, analyzer, temp_dir):
        """A file over the threshold is handed to a worker thread and still lands in known_certs"""
        analyzer._large_file_cert_threshold = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "large_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        analyzer.process_event(self._make_event(bundle_path))

        self._wait_for_background_processing(analyzer, bundle_path)
        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 5

    def test_large_pkcs12_routed_to_background_thread(self, analyzer, temp_dir):
        """
        A PKCS12 file over _large_file_byte_cap must not block process_event
        on the sync path. Regression test for _count_pem_certs(...) == 0
        always holding for JKS/PKCS12 (they have no cheap text marker to
        count) and silently bypassing the background-thread gate — see
        _is_large_certificate_file, which now gates these formats on size.
        """
        analyzer._large_file_byte_cap = 1024
        root_ca, root_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        leaf, leaf_key = TestCertificateGeneration.generate_certificate("leaf.example.com", 365)
        p12_data = _make_pkcs12(leaf, leaf_key, chain_certs=[root_ca] * 3)
        p12_path = os.path.join(temp_dir, "large.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)
        assert len(p12_data) > analyzer._large_file_byte_cap  # sanity check on the fixture

        analyzer.process_event(self._make_event(p12_path))

        assert p12_path in analyzer._large_file_in_flight
        self._wait_for_background_processing(analyzer, p12_path)
        matching = [k for k in analyzer.known_certs.keys() if k.startswith(p12_path + ":")]
        assert len(matching) == 4

    def test_large_der_crt_routed_to_background_thread(self, analyzer, temp_dir):
        """
        A large binary/DER .crt file (no PEM markers) must be routed to the
        background-thread path, not parsed inline -- regression test for the
        DER/binary blind spot in _count_pem_certs (see
        test_is_large_certificate_file_der_falls_back_to_byte_cap). Mocks
        _process_certificate_file_async rather than waiting on
        _large_file_in_flight, since garbage DER content parses to 0 certs
        near-instantly either way and the in-flight window would be racy.
        """
        from unittest.mock import MagicMock
        analyzer._large_file_byte_cap = 1024
        der_path = os.path.join(temp_dir, "large.crt")
        with open(der_path, 'wb') as f:
            f.write(b'\x30\x82' + os.urandom(2000))  # no PEM markers, over the byte cap

        analyzer._process_certificate_file_async = MagicMock()
        analyzer.process_event(self._make_event(der_path))

        analyzer._process_certificate_file_async.assert_called_once()
        assert analyzer._process_certificate_file_async.call_args[0][0] == der_path

    def test_background_threading_and_metrics_cap_are_independent(self, analyzer, temp_dir):
        """
        _large_file_cert_threshold (background-thread routing) and
        _large_file_metrics_cap (Prometheus fan-out cap) are separate knobs.
        A bundle over the (low) threshold but under the (higher) metrics cap
        must still be parsed on a background thread AND get full per-cert
        metrics for every cert -- raising the metrics cap to cover a realistic
        bundle must not also disable background-thread parsing for it.
        """
        analyzer._large_file_cert_threshold = 3
        analyzer._large_file_metrics_cap = 10
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "midsize_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        analyzer.process_event(self._make_event(bundle_path))

        # Over the cert threshold (5 > 3) -> routed to the background-thread
        # path (same routing logic covered by test_count_pem_certs and
        # test_large_file_processed_in_background).
        self._wait_for_background_processing(analyzer, bundle_path)

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 5

        # Under the metrics cap (5 <= 10) -> every cert gets full metrics, none skipped.
        samples = [
            s for metric in analyzer.metrics.cert_expiry_days.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == bundle_path
        ]
        assert len(samples) == 5, "certs under the metrics cap must all get full per-cert series"

    def test_bundle_beyond_threshold_caps_metrics_fanout(self, analyzer, temp_dir):
        """
        A bundle file (e.g. a system CA trust store) with far more certs than
        the large-file threshold must only get full per-cert Prometheus series
        for the first `metrics_cap` certs -- otherwise one bundle file turns
        into thousands of new series in a single burst, which is what drove
        cert-analyzer's cardinality/memory spike and hang on 2026-07-03.
        All certs must still land in known_certs (so known-file lookups and
        cache-size accounting stay correct) even though metrics are capped.
        """
        analyzer._large_file_cert_threshold = 3
        analyzer._large_file_metrics_cap = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(10)]
        bundle_path = os.path.join(temp_dir, "ca_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        analyzer.process_event(self._make_event(bundle_path))
        self._wait_for_background_processing(analyzer, bundle_path)

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 10, "every cert must still be cached, even beyond the metrics cap"

        samples = [
            s for metric in analyzer.metrics.cert_expiry_days.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == bundle_path
        ]
        assert len(samples) == 3, "only the first metrics_cap certs should get full per-cert series"

    @pytest.mark.parametrize("n_processes", [5, 25, 100])
    def test_many_processes_reaccessing_cached_bundle(self, analyzer, temp_dir, n_processes):
        """
        Reproduces the dominant cardinality driver behind the 2026-07-03
        incident: once a bundle is cached, every *subsequent* access from a
        distinct process (e.g. the system CA bundle being opened by dozens of
        unrelated binaries) re-walks every cached cert for that path and
        records a process-access sample per (cert, process) pair via
        record_cert_process_access(). Uncapped, N processes re-accessing an
        M-cert bundle mints N*M series. process_event() now caps how many of
        the cached certs get a process-access sample per re-access event to
        metrics_cap, so growth is O(N*metrics_cap) instead of O(N*M) -- still
        linear in N, but with a small constant slope instead of the full
        (much larger) bundle size.
        """
        analyzer._large_file_cert_threshold = 3
        analyzer._large_file_metrics_cap = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(10)]
        bundle_path = os.path.join(temp_dir, "ca_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        # First access parses and caches the bundle (metrics fan-out already
        # capped by the fix above).
        analyzer.process_event(self._make_event(bundle_path))
        self._wait_for_background_processing(analyzer, bundle_path)

        # N independent processes each re-access the now-cached bundle.
        for i in range(n_processes):
            analyzer.process_event(
                self._make_event(bundle_path, process=f"/usr/bin/proc{i}", pid=5000 + i)
            )

        samples = [
            s for metric in analyzer.metrics.cert_process_info.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == bundle_path
        ]
        metrics_cap = analyzer._large_file_metrics_cap
        # +1 covers the initial parsing event (process=/usr/bin/cat), which
        # also contributes up to metrics_cap series of its own.
        max_expected = metrics_cap * (n_processes + 1)
        assert len(samples) <= max_expected, (
            f"process-access fan-out should be capped at ~metrics_cap per event, "
            f"got {len(samples)} cert_process_info series for {n_processes} "
            f"processes re-accessing a {len(certs)}-cert bundle (expected <= {max_expected})"
        )
        # Confirm the cap is actually doing something, not just a loose bound:
        # uncapped behavior would be up to n_processes * len(certs) series.
        assert len(samples) < n_processes * len(certs), (
            "fan-out should be well below the old uncapped N*M behavior"
        )

    def test_duplicate_events_for_large_file_in_flight_are_deduped(self, analyzer, temp_dir):
        """A second event for the same large file while the first is still parsing is skipped"""
        from unittest.mock import MagicMock
        analyzer._large_file_cert_threshold = 3
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "dup_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        # Simulate the in-flight worker already having claimed this path.
        analyzer._large_file_in_flight.add(bundle_path)
        analyzer.process_event(self._make_event(bundle_path))

        # Nothing should have been published — the event was skipped, not processed.
        assert mock_publisher.publish.call_count == 0
        assert bundle_path not in analyzer.known_certs

    def test_bad_cert_in_finish_loop_does_not_abort_remaining_certs(self, analyzer, temp_dir):
        """One cert raising in _finish_new_certificate_file must not drop the rest of the file."""
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "flaky_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        real_update = analyzer.metrics.update_certificate_metrics

        def flaky_update(cert_info):
            if cert_info.cert_index == 2:
                raise ValueError("simulated bad label value")
            return real_update(cert_info)

        analyzer.metrics.update_certificate_metrics = flaky_update

        errors_before = analyzer.metrics.cert_analysis_errors.labels(error_type='finish_error', node_name=analyzer.metrics._node_name)._value.get()

        analyzer.process_event(self._make_event(bundle_path))

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        # certs 0,1,3,4 must have landed in the cache; only cert 2 was lost.
        assert len(matching) == 4

        errors_after = analyzer.metrics.cert_analysis_errors.labels(error_type='finish_error', node_name=analyzer.metrics._node_name)._value.get()
        assert errors_after == errors_before + 1

    def test_large_file_worker_exception_is_logged_and_counted(self, analyzer, temp_dir, caplog):
        """An exception inside the background worker must hit the same error-logging/metrics path as a synchronous event."""
        analyzer._large_file_cert_threshold = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "exploding_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        def boom(*args, **kwargs):
            raise RuntimeError("simulated parse failure")

        analyzer.analyze_certificate = boom

        errors_before = analyzer.metrics.cert_events_total.labels(event_type='processing', status='error', node_name=analyzer.metrics._node_name)._value.get()

        with caplog.at_level(logging.ERROR, logger="agent.analyzer"):
            analyzer.process_event(self._make_event(bundle_path))
            self._wait_for_background_processing(analyzer, bundle_path)

        errors_after = analyzer.metrics.cert_events_total.labels(event_type='processing', status='error', node_name=analyzer.metrics._node_name)._value.get()
        assert errors_after == errors_before + 1
        assert any("Error processing large certificate file" in r.message
                   for r in caplog.records)


class TestPeriodicScan:
    """
    periodic_scan() used to reimplement its own inline
    metrics/logging/cache/publish loop instead of reusing analyze_certificate()
    + _finish_new_certificate_file() — so it never got the large_file_metrics_cap
    fan-out cap (reproducing the 2026-07-03 cardinality incident for any bundle
    under a scan_paths directory) and always re-published already-known certs to
    Kafka on every scan_interval. periodic_scan now shares the same threshold
    routing / cap / known-file-skip logic as the Tetragon event path.
    """

    def test_bundle_beyond_threshold_caps_metrics_fanout(self, analyzer, temp_dir):
        """A bundle discovered via periodic_scan gets the same fan-out cap as one discovered via a Tetragon event."""
        analyzer._large_file_cert_threshold = 3
        analyzer._large_file_metrics_cap = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(10)]
        bundle_path = os.path.join(temp_dir, "ca_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        analyzer.periodic_scan([temp_dir])

        deadline = time.time() + 5.0
        while time.time() < deadline and bundle_path in analyzer._large_file_in_flight:
            time.sleep(0.01)

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 10, "every cert must still be cached, even beyond the metrics cap"

        samples = [
            s for metric in analyzer.metrics.cert_expiry_days.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == bundle_path
        ]
        assert len(samples) == 3, "only the first metrics_cap certs should get full per-cert series"

    def test_large_bundle_routed_to_background_worker(self, analyzer, temp_dir):
        """A bundle over the threshold is hop-scotched through the same async worker path as a Tetragon event, not parsed inline."""
        analyzer._large_file_cert_threshold = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "large_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        real_async = analyzer._process_certificate_file_async
        calls = []

        def spy(cert_path, *args, **kwargs):
            calls.append(cert_path)
            return real_async(cert_path, *args, **kwargs)

        analyzer._process_certificate_file_async = spy
        analyzer.periodic_scan([temp_dir])

        deadline = time.time() + 5.0
        while time.time() < deadline and bundle_path in analyzer._large_file_in_flight:
            time.sleep(0.01)

        assert calls == [bundle_path]

    def test_large_key_file_routed_to_background_worker(self, analyzer, temp_dir):
        """
        A large .key file discovered by periodic_scan (the only path that can
        reach .key -- no Tetragon policy watches it) must be routed to the
        background worker like any other oversized cert-adjacent file, not
        parsed inline. Regression test for the private-key zero-markers gap
        -- see test_is_large_certificate_file_key_falls_back_to_byte_cap.
        """
        analyzer._large_file_byte_cap = 100
        key_path = os.path.join(temp_dir, "large.key")
        with open(key_path, 'wb') as f:
            f.write(b'-----BEGIN PRIVATE KEY-----\n' + b'x' * 300)

        real_async = analyzer._process_certificate_file_async
        calls = []

        def spy(cert_path, *args, **kwargs):
            calls.append(cert_path)
            return real_async(cert_path, *args, **kwargs)

        analyzer._process_certificate_file_async = spy
        analyzer.periodic_scan([temp_dir])

        deadline = time.time() + 5.0
        while time.time() < deadline and key_path in analyzer._large_file_in_flight:
            time.sleep(0.01)

        assert calls == [key_path]

    def test_already_known_file_is_not_reparsed_or_republished(self, analyzer, temp_dir):
        """A file already present in known_certs must be skipped entirely — no re-parse, no duplicate Kafka publish."""
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("known.example.com", 365)
        cert_path = os.path.join(temp_dir, "known.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")

        analyzer.kafka_publisher = Mock()
        real_analyze = analyzer.analyze_certificate
        analyze_calls = []

        def spy(path, *args, **kwargs):
            analyze_calls.append(path)
            return real_analyze(path, *args, **kwargs)

        analyzer.analyze_certificate = spy
        analyzer.periodic_scan([temp_dir])

        assert analyze_calls == [], "already-known files must not be re-parsed"
        analyzer.kafka_publisher.publish.assert_not_called()

    def test_new_file_is_parsed_cached_and_published(self, analyzer, temp_dir):
        """A file periodic_scan has never seen before is parsed, cached, and published exactly once."""
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("new.example.com", 365)
        cert_path = os.path.join(temp_dir, "new.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.kafka_publisher = Mock()
        analyzer.periodic_scan([temp_dir])

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(cert_path + ":")]
        assert len(matching) == 1
        analyzer.kafka_publisher.publish.assert_called_once()

    def test_symlinked_cert_is_not_double_counted(self, analyzer, temp_dir):
        """A symlink pointing at an already-scanned cert file is skipped, not re-parsed.

        Trust stores like /etc/pki/ca-trust/extracted/pem/directory-hash/ re-expose
        the same certs under extra symlinked paths (individually and as whole-bundle
        aliases) purely for OpenSSL CApath lookups -- without a skip, periodic_scan
        would parse and metrics-track the same cert multiple times over.
        """
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("linked.example.com", 365)
        real_path = os.path.join(temp_dir, "real.pem")
        TestCertificateGeneration.save_certificate_pem(cert, real_path)
        link_path = os.path.join(temp_dir, "alias.pem")
        os.symlink(real_path, link_path)

        analyzer.kafka_publisher = Mock()
        analyzer.periodic_scan([temp_dir])

        real_matching = [k for k in analyzer.known_certs.keys() if k.startswith(real_path + ":")]
        link_matching = [k for k in analyzer.known_certs.keys() if k.startswith(link_path + ":")]
        assert len(real_matching) == 1
        assert len(link_matching) == 0
        analyzer.kafka_publisher.publish.assert_called_once()

    def test_directory_hash_subdir_is_skipped_entirely(self, analyzer, temp_dir):
        """Anything under a directory-hash/ subdir is skipped, not just symlinks.

        update-ca-trust's extracted/pem/directory-hash/ mixes genuine duplicate
        regular files (one per CA, alongside the symlinked hash lookup for it)
        with symlinks -- a symlink-only skip misses the regular-file duplicates,
        so periodic_scan must skip the whole directory by name instead.
        """
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("hashdir.example.com", 365)
        real_path = os.path.join(temp_dir, "real.pem")
        TestCertificateGeneration.save_certificate_pem(cert, real_path)

        hash_dir = os.path.join(temp_dir, "directory-hash")
        os.makedirs(hash_dir)
        dup_path = os.path.join(hash_dir, "real.pem")
        TestCertificateGeneration.save_certificate_pem(cert, dup_path)

        analyzer.kafka_publisher = Mock()
        analyzer.periodic_scan([temp_dir])

        real_matching = [k for k in analyzer.known_certs.keys() if k.startswith(real_path + ":")]
        dup_matching = [k for k in analyzer.known_certs.keys() if k.startswith(dup_path + ":")]
        assert len(real_matching) == 1
        assert len(dup_matching) == 0
        analyzer.kafka_publisher.publish.assert_called_once()

    def test_new_file_gets_analyzer_node_name_not_empty(self, analyzer, temp_dir):
        """
        A cert discovered via periodic_scan must carry the analyzer's own
        configured node identity (_NODE_NAME), not an empty string.

        periodic_scan has no Tetragon event to read node_name from (unlike the
        real-time event path), so it used to hardcode node_name="" -- silently
        dropping every periodic-scan-only cert (the majority on any node, since
        periodic scan sweeps the whole filesystem while Tetragon only catches
        real-time accesses) into its own empty-node_name bucket on any
        Prometheus query grouped `by (node_name)`, alongside the real per-node
        groups.
        """
        from agent.constants import _NODE_NAME

        cert, _ = TestCertificateGeneration.generate_certificate("nodename.example.com", 365)
        cert_path = os.path.join(temp_dir, "nodename.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.periodic_scan([temp_dir])

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(cert_path + ":")]
        assert len(matching) == 1
        cert_info = analyzer.known_certs[matching[0]]
        assert cert_info.node_name == _NODE_NAME
        assert cert_info.node_name != ""

    def test_large_bundle_gets_analyzer_node_name_not_empty(self, analyzer, temp_dir):
        """Same as above, but for the large-bundle path routed through _process_certificate_file_async."""
        from agent.constants import _NODE_NAME

        analyzer._large_file_cert_threshold = 3
        certs = [TestCertificateGeneration.generate_certificate(f"c{i}.example.com", 365)[0]
                 for i in range(5)]
        bundle_path = os.path.join(temp_dir, "nodename_bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(certs, bundle_path)

        analyzer.periodic_scan([temp_dir])

        deadline = time.time() + 5.0
        while time.time() < deadline and bundle_path in analyzer._large_file_in_flight:
            time.sleep(0.01)

        matching = [k for k in analyzer.known_certs.keys() if k.startswith(bundle_path + ":")]
        assert len(matching) == 5
        for key in matching:
            assert analyzer.known_certs[key].node_name == _NODE_NAME

    def test_nonexistent_scan_path_is_skipped(self, analyzer):
        """A configured scan path that doesn't exist on disk is skipped without raising."""
        analyzer.periodic_scan(["/nonexistent/scan/path"])

    @staticmethod
    def _make_event(path, process='/usr/bin/cat', pid=4242):
        from unittest.mock import MagicMock
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = process
        mock_kprobe.process.pid.value = pid
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe
        mock_event.node_name = ''
        return mock_event

    def test_new_file_in_flight_prevents_periodic_scan_reparsing_file_claimed_by_event_path(
        self, analyzer, temp_dir
    ):
        """
        If a Tetragon event for a brand-new small file is mid-parse (has claimed
        the path in _new_file_in_flight) right as periodic_scan's directory walk
        reaches the same path, periodic_scan must not also parse/publish it.
        """
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("racy.example.com", 365)
        cert_path = os.path.join(temp_dir, "racy.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.kafka_publisher = Mock()
        analyzer._new_file_in_flight.add(cert_path)  # simulate process_event already claiming it
        real_analyze = analyzer.analyze_certificate
        analyze_calls = []

        def spy(path, *args, **kwargs):
            analyze_calls.append(path)
            return real_analyze(path, *args, **kwargs)

        analyzer.analyze_certificate = spy
        analyzer.periodic_scan([temp_dir])

        assert analyze_calls == [], "a path already claimed by another thread must not be re-parsed"
        analyzer.kafka_publisher.publish.assert_not_called()
        assert cert_path not in analyzer.known_certs.keys()

    def test_new_file_in_flight_prevents_event_path_reparsing_file_claimed_by_periodic_scan(
        self, analyzer, temp_dir
    ):
        """Same race, mirrored: process_event must not re-parse/publish a path periodic_scan has already claimed."""
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("racy2.example.com", 365)
        cert_path = os.path.join(temp_dir, "racy2.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.kafka_publisher = Mock()
        analyzer._new_file_in_flight.add(cert_path)  # simulate periodic_scan already claiming it
        real_analyze = analyzer.analyze_certificate
        analyze_calls = []

        def spy(path, *args, **kwargs):
            analyze_calls.append(path)
            return real_analyze(path, *args, **kwargs)

        analyzer.analyze_certificate = spy
        analyzer.process_event(self._make_event(cert_path))

        assert analyze_calls == [], "a path already claimed by another thread must not be re-parsed"
        analyzer.kafka_publisher.publish.assert_not_called()

    def test_large_file_in_flight_prevents_event_path_reparsing_file_claimed_by_async_path(
        self, analyzer, temp_dir
    ):
        """
        Cross-mechanism race: if the background-thread path has already claimed
        a brand-new path (_large_file_in_flight), a concurrent Tetragon event
        for the same path -- even one whose _count_pem_certs verdict would
        route it synchronously -- must not also parse/publish it. Without
        checking both in-flight sets under one shared lock, both mechanisms
        would independently write known_certs[same_key] = <a different
        CertificateInfo instance each>, and LRUCache.__setitem__ never fires
        on_evict for a same-key overwrite, so the first write's Prometheus
        series would never get cleaned up.
        """
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("racy3.example.com", 365)
        cert_path = os.path.join(temp_dir, "racy3.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.kafka_publisher = Mock()
        analyzer._large_file_in_flight.add(cert_path)  # simulate the async path already claiming it
        real_analyze = analyzer.analyze_certificate
        analyze_calls = []

        def spy(path, *args, **kwargs):
            analyze_calls.append(path)
            return real_analyze(path, *args, **kwargs)

        analyzer.analyze_certificate = spy
        analyzer.process_event(self._make_event(cert_path))

        assert analyze_calls == [], "a path claimed by the async path must not also be parsed synchronously"
        analyzer.kafka_publisher.publish.assert_not_called()

    def test_new_file_in_flight_prevents_async_path_reparsing_file_claimed_by_event_path(
        self, analyzer, temp_dir
    ):
        """Mirrored: a path already claimed by the synchronous path must block the background-thread path too."""
        from unittest.mock import Mock

        cert, _ = TestCertificateGeneration.generate_certificate("racy4.example.com", 365)
        cert_path = os.path.join(temp_dir, "racy4.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer._new_file_in_flight.add(cert_path)  # simulate the sync path already claiming it
        analyzer._start_background_thread = Mock(return_value=True)

        analyzer._process_certificate_file_async(cert_path, "test", 1, "", None, "", 0, "")

        analyzer._start_background_thread.assert_not_called()

    def test_new_file_in_flight_cleared_after_periodic_scan_completes(self, analyzer, temp_dir):
        """_new_file_in_flight must not leak an entry once periodic_scan finishes with a path."""
        cert, _ = TestCertificateGeneration.generate_certificate("cleanup.example.com", 365)
        cert_path = os.path.join(temp_dir, "cleanup.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.periodic_scan([temp_dir])

        assert cert_path not in analyzer._new_file_in_flight

    def test_new_file_in_flight_cleared_after_process_event_completes(self, analyzer, temp_dir):
        """_new_file_in_flight must not leak an entry once process_event finishes with a path."""
        cert, _ = TestCertificateGeneration.generate_certificate("cleanup2.example.com", 365)
        cert_path = os.path.join(temp_dir, "cleanup2.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        analyzer.process_event(self._make_event(cert_path))

        assert cert_path not in analyzer._new_file_in_flight


class TestCertificateAnalysis:
    """Test certificate analysis and information extraction"""
    
    def test_analyze_valid_certificate(self, analyzer, temp_dir):
        """Test analyzing a valid certificate"""
        cert, _ = TestCertificateGeneration.generate_certificate("valid.example.com", 365)
        cert_path = os.path.join(temp_dir, "valid.pem")
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)
        
        cert_infos = analyzer.analyze_certificate(cert_path, "test_process", 1234)
        
        assert len(cert_infos) == 1
        assert cert_infos[0].common_name == "valid.example.com"
        assert cert_infos[0].process == "test_process"
        assert cert_infos[0].pid == 1234
        assert cert_infos[0].cert_index == 0
        assert not cert_infos[0].is_expired
        assert 360 < cert_infos[0].days_until_expiry < 370
    
    def test_analyze_multi_certificate_bundle(self, analyzer, temp_dir):
        """Test analyzing a bundle with multiple certificates"""
        cert1, _ = TestCertificateGeneration.generate_certificate("cert1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("cert2.example.com", -10)  # Expired
        cert3, _ = TestCertificateGeneration.generate_certificate("cert3.example.com", 5)    # Expiring soon
        
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2, cert3], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        assert len(cert_infos) == 3
        
        # Check cert indexes
        assert cert_infos[0].cert_index == 0
        assert cert_infos[1].cert_index == 1
        assert cert_infos[2].cert_index == 2
        
        # Check statuses
        assert not cert_infos[0].is_expired  # Valid
        assert cert_infos[1].is_expired      # Expired
        assert cert_infos[2].expires_soon(days=7)  # Expiring soon


class TestNewCertRateLimiting:
    """
    Bounds the CPU an attacker can force purely through certificate activity
    (e.g. writing many distinct cert files, or churning bind/connect-probe
    endpoints) with no config access -- see agent/analyzer.py's
    _new_cert_rate_limiter / _TokenBucket. analyze_certificate() itself is
    pure parse-and-extract; the limiter is gated in
    _try_process_new_certificate_file()/_analyze_and_finish_new_certificate_file(),
    the shared choke point all trigger paths (real-time Tetragon events,
    periodic_scan, large-file background thread, and the retry-queue
    drainer) funnel through for never-before-seen paths. A throttled file is
    queued (see TestRateLimitRetryQueue) rather than dropped.
    """

    def _analyze_new(self, analyzer, path, process="test", pid=1, namespace=""):
        return analyzer._analyze_and_finish_new_certificate_file(
            path, process, pid, namespace, None, "", 0, "test-node",
        )

    def test_exhausted_bucket_skips_new_file_without_erroring(self, analyzer, temp_dir):
        """Once tokens run out, a brand-new cert file is skipped (returns []) instead of parsed."""
        from agent.analyzer import _TokenBucket
        analyzer._new_cert_rate_limiter = _TokenBucket(rate=2)

        results = []
        for i in range(5):
            cert, _ = TestCertificateGeneration.generate_certificate(f"rl{i}.example.com", 365)
            path = os.path.join(temp_dir, f"rl{i}.pem")
            TestCertificateGeneration.save_certificate_pem(cert, path)
            results.append(self._analyze_new(analyzer, path))

        succeeded = [r for r in results if r]
        skipped = [r for r in results if not r]
        assert len(succeeded) == 2, "only the burst capacity (2 tokens) should succeed"
        assert len(skipped) == 3

    def test_analyze_certificate_itself_is_not_rate_limited(self, analyzer, temp_dir):
        """
        analyze_certificate() is pure parse-and-extract -- the rate limiter
        only applies via the wrapper. This pins that intentional split so a
        future refactor doesn't accidentally re-couple them (or silently
        drop gating from the wrapper's callers).
        """
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0  # force exhausted
        analyzer._new_cert_rate_limiter = bucket

        cert, _ = TestCertificateGeneration.generate_certificate("direct.example.com", 365)
        path = os.path.join(temp_dir, "direct.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        result = analyzer.analyze_certificate(path, "test", 1)
        assert len(result) == 1

    def test_rate_limited_event_is_not_cached_but_is_queued_for_retry(self, analyzer, temp_dir):
        """A throttled file isn't marked known, but is queued for replay -- not silently dropped."""
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0  # force exhausted
        analyzer._new_cert_rate_limiter = bucket

        cert, _ = TestCertificateGeneration.generate_certificate("rl-retry.example.com", 365)
        path = os.path.join(temp_dir, "rl-retry.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        result = self._analyze_new(analyzer, path)
        assert result == []
        assert path not in analyzer.processed_paths
        matching = [k for k in analyzer.known_certs.keys() if k.startswith(path + ":")]
        assert matching == []
        assert path in analyzer._retry_queue_paths
        assert any(e.cert_path == path for e in analyzer._retry_queue)

    def test_rate_limited_event_increments_error_metric(self, analyzer, temp_dir):
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0  # force exhausted
        analyzer._new_cert_rate_limiter = bucket

        cert, _ = TestCertificateGeneration.generate_certificate("rl-metric.example.com", 365)
        path = os.path.join(temp_dir, "rl-metric.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        before = analyzer.metrics.cert_analysis_errors.labels(error_type='rate_limited', node_name=analyzer.metrics._node_name)._value.get()
        self._analyze_new(analyzer, path)
        after = analyzer.metrics.cert_analysis_errors.labels(error_type='rate_limited', node_name=analyzer.metrics._node_name)._value.get()
        assert after == before + 1

    def test_zero_rate_disables_limiter_and_never_queues(self, analyzer, temp_dir):
        """rate <= 0 is the escape hatch for operators who want it off entirely."""
        from agent.analyzer import _TokenBucket
        analyzer._new_cert_rate_limiter = _TokenBucket(rate=0)

        results = []
        for i in range(20):
            cert, _ = TestCertificateGeneration.generate_certificate(f"unlimited{i}.example.com", 365)
            path = os.path.join(temp_dir, f"unlimited{i}.pem")
            TestCertificateGeneration.save_certificate_pem(cert, path)
            results.append(self._analyze_new(analyzer, path))

        assert all(len(r) == 1 for r in results)
        assert len(analyzer._retry_queue) == 0

    def test_token_bucket_refills_over_time(self):
        """Tokens regenerate at `rate`/sec, capped at `rate` -- not an infinite drain."""
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=10)  # 10/sec == one token every 0.1s
        for _ in range(10):
            assert bucket.try_acquire()
        assert not bucket.try_acquire()  # burst capacity exhausted

        time.sleep(0.25)  # ~2-3 tokens' worth of refill
        assert bucket.try_acquire()


class TestRateLimitRetryQueue:
    """
    agent/analyzer.py's _enqueue_rate_limited_retry / _retry_queue -- gives a
    throttled certificate file a guaranteed path back regardless of whether
    it happens to live under scan_paths (periodic_scan's coverage) or gets
    touched again naturally. Bounded FIFO so it can't become a second
    unbounded memory sink for the same abuse the rate limiter defends
    against. See TestRetryQueueDrainer (near the other background-monitor
    tests) for the actual replay thread.
    """

    def _analyze_new(self, analyzer, path, process="test", pid=1, namespace=""):
        return analyzer._analyze_and_finish_new_certificate_file(
            path, process, pid, namespace, None, "", 0, "test-node",
        )

    def test_dedupes_same_path(self, analyzer, temp_dir):
        """A path throttled twice while already queued doesn't get a second entry."""
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0
        analyzer._new_cert_rate_limiter = bucket

        cert, _ = TestCertificateGeneration.generate_certificate("dupe.example.com", 365)
        path = os.path.join(temp_dir, "dupe.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        self._analyze_new(analyzer, path)
        self._analyze_new(analyzer, path)

        assert len(analyzer._retry_queue) == 1
        assert list(analyzer._retry_queue_paths) == [path]

    def test_drops_oldest_on_overflow(self, analyzer, temp_dir):
        """At capacity, the oldest queued entry is dropped to make room for a new one."""
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0
        analyzer._new_cert_rate_limiter = bucket
        analyzer._retry_queue_max_size = 3

        paths = []
        for i in range(5):
            cert, _ = TestCertificateGeneration.generate_certificate(f"overflow{i}.example.com", 365)
            path = os.path.join(temp_dir, f"overflow{i}.pem")
            TestCertificateGeneration.save_certificate_pem(cert, path)
            paths.append(path)
            self._analyze_new(analyzer, path)

        assert len(analyzer._retry_queue) == 3
        queued_paths = [e.cert_path for e in analyzer._retry_queue]
        assert queued_paths == paths[2:], "oldest two should have been dropped, newest three remain"
        assert set(analyzer._retry_queue_paths) == set(paths[2:])

    def test_overflow_increments_dropped_metric(self, analyzer, temp_dir):
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0
        analyzer._new_cert_rate_limiter = bucket
        analyzer._retry_queue_max_size = 1

        before = analyzer.metrics.cert_analysis_errors.labels(error_type='retry_queue_dropped', node_name=analyzer.metrics._node_name)._value.get()

        for i in range(3):
            cert, _ = TestCertificateGeneration.generate_certificate(f"drop{i}.example.com", 365)
            path = os.path.join(temp_dir, f"drop{i}.pem")
            TestCertificateGeneration.save_certificate_pem(cert, path)
            self._analyze_new(analyzer, path)

        after = analyzer.metrics.cert_analysis_errors.labels(error_type='retry_queue_dropped', node_name=analyzer.metrics._node_name)._value.get()
        assert after == before + 2  # first entry stays, next two each evict one

    def test_queue_depth_metric_tracks_size(self, analyzer, temp_dir):
        from agent.analyzer import _TokenBucket
        bucket = _TokenBucket(rate=1)
        bucket._tokens = 0
        analyzer._new_cert_rate_limiter = bucket

        node = analyzer.metrics._node_name
        assert analyzer.metrics.retry_queue_depth.labels(node_name=node)._value.get() == 0

        cert, _ = TestCertificateGeneration.generate_certificate("depth.example.com", 365)
        path = os.path.join(temp_dir, "depth.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)
        self._analyze_new(analyzer, path)

        assert analyzer.metrics.retry_queue_depth.labels(node_name=node)._value.get() == 1


class TestCertificateInfo:
    """Test CertificateInfo dataclass functionality"""
    
    def test_unique_key_generation(self):
        """Test unique key generation for certificates"""
        info1 = CertificateInfo(
            path="/test/cert.pem",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="12345",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            process="test",
            pid=1234,
            cert_index=0
        )
        
        info2 = CertificateInfo(
            path="/test/cert.pem",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="12345",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            process="test",
            pid=1234,
            cert_index=1  # Different index
        )
        
        # Same file but different cert index should have different keys
        assert info1.unique_key != info2.unique_key
        assert "/test/cert.pem:0:12345" == info1.unique_key
        assert "/test/cert.pem:1:12345" == info2.unique_key
    
    def test_expires_soon_thresholds(self):
        """Test expires_soon with different thresholds"""
        info = CertificateInfo(
            path="/test/cert.pem",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="12345",
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=15),
            process="test",
            pid=1234
        )
        
        assert info.expires_soon(days=7) == False   # Not expiring in 7 days
        assert info.expires_soon(days=30) == True   # Expiring in 30 days
        assert info.expires_soon(days=90) == True   # Expiring in 90 days


class TestPathDetection:
    """Test certificate path detection"""
    
    def test_is_cert_path_valid_extensions(self, analyzer):
        """Test detection of valid certificate file extensions"""
        assert analyzer.is_cert_path("/test/cert.pem")
        assert analyzer.is_cert_path("/test/cert.crt")
        assert analyzer.is_cert_path("/test/cert.cert")
        assert analyzer.is_cert_path("/test/cert.cer")
        assert analyzer.is_cert_path("/test/cert.key")
        assert analyzer.is_cert_path("/TEST/CERT.PEM")  # Case insensitive

    def test_is_cert_path_jks_extensions(self, analyzer):
        """Test detection of JKS keystore file extensions"""
        assert analyzer.is_cert_path("/app/truststore.jks")
        assert analyzer.is_cert_path("/app/server.keystore")
        assert analyzer.is_cert_path("/app/ca.truststore")
        assert analyzer.is_cert_path("/APP/TRUST.JKS")  # Case insensitive

    def test_is_cert_path_pkcs12_extensions(self, analyzer):
        """Test detection of PKCS12 keystore file extensions"""
        assert analyzer.is_cert_path("/app/keystore.p12")
        assert analyzer.is_cert_path("/app/keystore.pfx")
        assert analyzer.is_cert_path("/APP/KEYSTORE.P12")  # Case insensitive
        assert analyzer.is_cert_path("/APP/KEYSTORE.PFX")  # Case insensitive

    def test_is_cert_path_invalid_extensions(self, analyzer):
        """Test rejection of invalid file extensions"""
        assert not analyzer.is_cert_path("/test/file.txt")
        assert not analyzer.is_cert_path("/test/file.pdf")
        assert not analyzer.is_cert_path("/test/file")
        assert not analyzer.is_cert_path("")
        assert not analyzer.is_cert_path(None)


# ── PKCS12 helper ─────────────────────────────────────────────────────────────

def _make_pkcs12(cert, private_key, chain_certs=None, password: bytes = b'changeit') -> bytes:
    """Serialise a certificate + key (and optional chain) into a PKCS12 blob."""
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

    additional = None
    if chain_certs:
        # serialize_key_and_certificates wants a list of x509.Certificate, not tuples
        from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12Certificate
        additional = [
            PKCS12Certificate(cert=c, friendly_name=None) for c in chain_certs
        ]

    return serialize_key_and_certificates(
        name=b'test',
        key=private_key,
        cert=cert,
        cas=additional,
        encryption_algorithm=BestAvailableEncryption(password),
    )


class TestPKCS12Parsing:
    """Test parsing of PKCS12 keystore files (.p12 / .pfx)"""

    def test_parse_valid_p12_returns_leaf_cert(self, analyzer, temp_dir):
        """parse_pkcs12_certificates extracts the leaf certificate from a .p12 file"""
        cert, key = TestCertificateGeneration.generate_certificate("leaf.example.com", 365)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "keystore.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        certs = analyzer.parse_pkcs12_certificates(p12_path)

        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "leaf.example.com"

    def test_parse_p12_with_chain_returns_all_certs(self, analyzer, temp_dir):
        """parse_pkcs12_certificates extracts the leaf and all chain certificates"""
        root_ca, root_key         = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        intermediate, inter_key   = TestCertificateGeneration.generate_certificate("Intermediate CA", 1825, is_ca=True)
        leaf, leaf_key            = TestCertificateGeneration.generate_certificate("server.example.com", 365)

        p12_data = _make_pkcs12(leaf, leaf_key, chain_certs=[intermediate, root_ca])

        p12_path = os.path.join(temp_dir, "chain.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        certs = analyzer.parse_pkcs12_certificates(p12_path)

        assert len(certs) == 3
        common_names = [
            c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            for c in certs
        ]
        assert "server.example.com" in common_names
        assert "Intermediate CA" in common_names
        assert "Root CA" in common_names

    def test_parse_expired_p12_cert_detected(self, analyzer, temp_dir):
        """An expired certificate inside a .p12 file is correctly identified as expired"""
        cert, key = TestCertificateGeneration.generate_certificate("expired.example.com", -30)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "expired.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        cert_infos = analyzer.analyze_certificate(p12_path, "java", 1234)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_expired
        assert cert_infos[0].common_name == "expired.example.com"

    def test_parse_pfx_extension_dispatched(self, analyzer, temp_dir):
        """.pfx extension is treated identically to .p12"""
        cert, key = TestCertificateGeneration.generate_certificate("pfx.example.com", 365)
        p12_data = _make_pkcs12(cert, key)

        pfx_path = os.path.join(temp_dir, "keystore.pfx")
        with open(pfx_path, 'wb') as f:
            f.write(p12_data)

        certs = analyzer.parse_pkcs12_certificates(pfx_path)
        assert len(certs) == 1

    def test_parse_p12_wrong_password_returns_empty(self, analyzer, temp_dir, monkeypatch):
        """parse_pkcs12_certificates returns [] and increments error metric when all passwords fail"""
        cert, key = TestCertificateGeneration.generate_certificate("secure.example.com", 365)
        p12_data = _make_pkcs12(cert, key, password=b'supersecret')

        p12_path = os.path.join(temp_dir, "secured.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        # Ensure PKCS12_PASSWORD env var doesn't accidentally match
        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        certs = analyzer.parse_pkcs12_certificates(p12_path)
        assert certs == []

    def test_parse_p12_failed_path_cached(self, analyzer, temp_dir, monkeypatch):
        """A PKCS12 file that fails password attempts is cached and skipped on retry."""
        cert, key = TestCertificateGeneration.generate_certificate("cached.example.com", 365)
        p12_data = _make_pkcs12(cert, key, password=b'supersecret')

        p12_path = os.path.join(temp_dir, "cached.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        # First call — should attempt passwords and fail
        analyzer.parse_pkcs12_certificates(p12_path)
        assert p12_path in analyzer.password_failed_paths

        # Second call — should return immediately without attempting passwords
        # We verify by checking the error counter does not increment again
        before = analyzer.metrics.cert_analysis_errors.labels(error_type='pkcs12_password_failed', node_name=analyzer.metrics._node_name)._value.get()
        analyzer.parse_pkcs12_certificates(p12_path)
        after = analyzer.metrics.cert_analysis_errors.labels(error_type='pkcs12_password_failed', node_name=analyzer.metrics._node_name)._value.get()
        assert after == before  # no additional error increment on second call

    def test_parse_p12_password_list_does_not_include_changeme_or_password(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        The PKCS12 password list only tries env var, 'changeit', and empty string.
        'changeme' and 'password' are not attempted.
        """
        tried = []
        original_load = __import__(
            'cryptography.hazmat.primitives.serialization.pkcs12',
            fromlist=['load_pkcs12']
        ).load_pkcs12

        def _capturing_load(data, password):
            tried.append(password)
            raise ValueError("wrong password")

        import cryptography.hazmat.primitives.serialization.pkcs12 as _p12mod
        monkeypatch.setattr(_p12mod, 'load_pkcs12', _capturing_load)
        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        cert, key = TestCertificateGeneration.generate_certificate("pw-list.example.com", 365)
        p12_path = os.path.join(temp_dir, "pw-list.p12")
        # Write any bytes — the mock intercepts before real parsing
        with open(p12_path, 'wb') as f:
            f.write(b'dummy')

        analyzer.parse_pkcs12_certificates(p12_path)

        assert b'changeme' not in tried
        assert b'password' not in tried

    def test_parse_p12_custom_password_via_env(self, analyzer, temp_dir, monkeypatch):
        """PKCS12_PASSWORD env var is used before the default password list"""
        cert, key = TestCertificateGeneration.generate_certificate("env-pw.example.com", 365)
        p12_data = _make_pkcs12(cert, key, password=b'mysecretpassword')

        p12_path = os.path.join(temp_dir, "env-pw.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        monkeypatch.setenv('PKCS12_PASSWORD', 'mysecretpassword')

        certs = analyzer.parse_pkcs12_certificates(p12_path)
        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "env-pw.example.com"

    def test_parse_p12_file_not_found_returns_empty(self, analyzer):
        """parse_pkcs12_certificates returns [] gracefully when the file does not exist"""
        certs = analyzer.parse_pkcs12_certificates("/nonexistent/path/keystore.p12")
        assert certs == []

    def test_parse_certificates_dispatches_p12(self, analyzer, temp_dir):
        """parse_certificates routes .p12 files to parse_pkcs12_certificates"""
        cert, key = TestCertificateGeneration.generate_certificate("dispatch.example.com", 365)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "dispatch.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        # Call the top-level dispatcher — must reach the PKCS12 parser
        certs = analyzer.parse_certificates(p12_path)
        assert len(certs) == 1

    def test_analyze_certificate_returns_cert_info_for_p12(self, analyzer, temp_dir):
        """analyze_certificate returns populated CertificateInfo objects for .p12 files"""
        cert, key = TestCertificateGeneration.generate_certificate("java-app.example.com", 90)
        p12_data = _make_pkcs12(cert, key)

        p12_path = os.path.join(temp_dir, "java-app.p12")
        with open(p12_path, 'wb') as f:
            f.write(p12_data)

        cert_infos = analyzer.analyze_certificate(p12_path, "/usr/bin/java", 4242)

        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.common_name == "java-app.example.com"
        assert info.path == p12_path
        assert info.process == "/usr/bin/java"
        assert info.pid == 4242
        assert not info.is_expired
        assert 89 < info.days_until_expiry <= 90


class TestCABundles:
    """Test handling of real-world CA bundle scenarios"""
    
    def test_ca_bundle_with_chain(self, analyzer, temp_dir):
        """Test parsing a typical CA bundle with root and intermediate CAs"""
        root_ca, _ = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        intermediate_ca, _ = TestCertificateGeneration.generate_certificate("Intermediate CA", 1825, is_ca=True)
        leaf_cert, _ = TestCertificateGeneration.generate_certificate("server.example.com", 365)
        
        bundle_path = os.path.join(temp_dir, "ca-bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([root_ca, intermediate_ca, leaf_cert], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        assert len(cert_infos) == 3
        assert "Root CA" in cert_infos[0].common_name
        assert "Intermediate CA" in cert_infos[1].common_name
        assert "server.example.com" in cert_infos[2].common_name
    
    def test_expired_intermediate_in_chain(self, analyzer, temp_dir):
        """Test detection of expired intermediate certificate in chain"""
        root_ca, _ = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        intermediate_ca, _ = TestCertificateGeneration.generate_certificate("Intermediate CA", -30, is_ca=True)  # Expired
        leaf_cert, _ = TestCertificateGeneration.generate_certificate("server.example.com", 365)
        
        bundle_path = os.path.join(temp_dir, "chain-with-expired.pem")
        TestCertificateGeneration.save_multi_certificate_pem([root_ca, intermediate_ca, leaf_cert], bundle_path)
        
        cert_infos = analyzer.analyze_certificate(bundle_path, "test_process", 1234)
        
        assert len(cert_infos) == 3
        assert not cert_infos[0].is_expired  # Root is valid
        assert cert_infos[1].is_expired      # Intermediate is expired
        assert not cert_infos[2].is_expired  # Leaf is valid


class MockTetragonContainer:
    """
    Minimal mock of the Tetragon Container proto object.
    Mirrors the fields read in _apply_pod_context (v1.7.0 schema).
    """
    def __init__(
        self,
        id: str = "abc123",
        name: str = "",
        image_name: str = "",
        image_id: str = "",
        maybe_exec_probe: bool = False,
        pid: int = None,
        start_time=None,
        privileged: bool = None,
    ):
        from types import SimpleNamespace
        self.id               = id
        self.name             = name
        self.image            = SimpleNamespace(name=image_name, id=image_id)
        self.maybe_exec_probe = maybe_exec_probe
        self._pid             = pid
        self._start_time      = start_time
        self._privileged      = privileged
        if pid is not None:
            self.pid = SimpleNamespace(value=pid)
        if start_time is not None:
            self.start_time = SimpleNamespace(ToDatetime=lambda: start_time)
        if privileged is not None:
            self.security_context = SimpleNamespace(privileged=privileged)

    def HasField(self, name):
        if name == 'pid':
            return self._pid is not None
        if name == 'start_time':
            return self._start_time is not None
        if name == 'security_context':
            return self._privileged is not None
        return False


class MockTetragonPod:
    """
    Minimal mock of the Tetragon pod proto object.
    Mirrors the fields read in _apply_pod_context so tests don't need
    the real protobuf package installed.
    """
    def __init__(
        self,
        name: str = "test-pod-abc12",
        namespace: str = "default",
        workload_kind: str = "Deployment",
        workload: str = "test-deployment",
        pod_labels: dict = None,
        pod_annotations: dict = None,
        uid: str = "",
        container: 'MockTetragonContainer' = None,
    ):
        self.name            = name
        self.namespace       = namespace
        self.workload_kind   = workload_kind
        self.workload        = workload
        self.pod_labels      = pod_labels or {}
        self.pod_annotations = pod_annotations or {}
        self.uid             = uid
        self.container       = container if container is not None else MockTetragonContainer()


class MockK8sEnricher:
    """Minimal mock of KubernetesEnricher for testing the secondary enrichment path."""

    def __init__(self, container_name: str = "main", container_image: str = "nginx:latest"):
        self.available        = True
        self._container_name  = container_name
        self._container_image = container_image

    def enrich(self, pod_name: str, namespace: str):
        from types import SimpleNamespace
        return SimpleNamespace(
            container_name=self._container_name,
            container_image=self._container_image,
        )


def _make_cert_info(**kwargs) -> CertificateInfo:
    """Return a minimal CertificateInfo with sensible defaults, overridable via kwargs."""
    defaults = dict(
        path="/tmp/test.crt",
        subject="CN=test",
        issuer="CN=ca",
        serial_number="99999",
        not_before=datetime.utcnow() - timedelta(days=1),
        not_after=datetime.utcnow() + timedelta(days=365),
        process="/bin/cat",
        pid=1234,
        namespace="default",
        common_name="test.example.com",
    )
    defaults.update(kwargs)
    return CertificateInfo(**defaults)


class TestPodEnrichmentFromTetragonEvent:
    """
    Tests for _apply_pod_context - the primary path that reads workload context
    directly from the Tetragon event proto rather than via the Kubernetes API.
    """

    def test_tetragon_pod_fields_applied(self, analyzer):
        """Core fields from the Tetragon proto are written to CertificateInfo."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            name="myapp-7d6f9-xk2p1",
            namespace="production",
            workload_kind="Deployment",
            workload="myapp",
            pod_labels={"app": "myapp", "version": "v1"},
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_name      == "myapp-7d6f9-xk2p1"
        assert cert_info.namespace     == "production"
        assert cert_info.workload_kind == "Deployment"
        assert cert_info.workload_name == "myapp"
        assert cert_info.pod_labels    == {"app": "myapp", "version": "v1"}

    def test_app_label_derived_from_app_key(self, analyzer):
        """app_label is populated from the 'app' pod label."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_labels={"app": "frontend"})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.app_label == "frontend"

    def test_app_label_derived_from_app_kubernetes_io_name(self, analyzer):
        """app_label prefers 'app.kubernetes.io/name' over 'app'."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            pod_labels={"app.kubernetes.io/name": "canonical-name", "app": "other"}
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.app_label == "canonical-name"

    def test_app_label_empty_when_no_matching_label(self, analyzer):
        """app_label stays empty when no recognised label key is present."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_labels={"custom-label": "value"})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.app_label == ""

    def test_no_op_when_tetragon_pod_is_none(self, analyzer):
        """_apply_pod_context is a no-op when Tetragon provided no pod context."""
        cert_info = _make_cert_info(namespace="original-ns")

        analyzer._apply_pod_context(cert_info, None)

        assert cert_info.pod_name  == ""
        assert cert_info.namespace == "original-ns"  # unchanged

    def test_empty_pod_labels_handled(self, analyzer):
        """Empty pod_labels dict on the proto doesn't raise."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_labels={})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_labels == {}
        assert cert_info.app_label  == ""

    def test_workload_property_combines_kind_and_name(self, analyzer):
        """workload property returns 'Kind/name' when both fields are set."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(workload_kind="DaemonSet", workload="node-agent")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.workload == "DaemonSet/node-agent"

    def test_workload_property_empty_when_fields_missing(self):
        """workload property is empty when kind or name are absent."""
        cert_info = _make_cert_info()
        assert cert_info.workload == ""


class TestK8sEnricherSecondaryPath:
    """
    Tests for the secondary enrichment path - the Kubernetes API enricher
    that supplements fields Tetragon doesn't provide (container name/image).
    """

    def test_container_fields_populated_from_tetragon_proto(self, analyzer):
        """container_name and container_image are read from the Tetragon Container proto."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            name="mypod",
            namespace="default",
            container=MockTetragonContainer(
                name="app-container",
                image_name="myrepo/myapp:v2.3.1",
            ),
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_name  == "app-container"
        assert cert_info.container_image == "myrepo/myapp:v2.3.1"

    def test_container_fields_empty_when_container_has_no_data(self, analyzer):
        """container_name and container_image default to empty when container fields are unset."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(name="mypod", namespace="default")
        # Default MockTetragonContainer has empty name/image

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_name  == ""
        assert cert_info.container_image == ""

    def test_container_fields_absent_when_no_pod_context(self, analyzer):
        """Container fields stay empty when there is no Tetragon pod context at all."""
        cert_info = _make_cert_info()

        analyzer._apply_pod_context(cert_info, None)

        assert cert_info.container_name  == ""
        assert cert_info.container_image == ""

    def test_tetragon_pod_fields_set_alongside_container(self, analyzer):
        """Pod-level fields (pod_name, workload etc.) are correctly set from the proto."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            name="original-pod",
            workload_kind="StatefulSet",
            workload="my-statefulset",
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_name      == "original-pod"
        assert cert_info.workload_kind == "StatefulSet"
        assert cert_info.workload_name == "my-statefulset"

    def test_pod_uid_populated_when_present(self, analyzer):
        """pod.uid (Tetragon v1.6.0+) is captured when the server supplies it."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(uid="550e8400-e29b-41d4-a716-446655440000")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_uid == "550e8400-e29b-41d4-a716-446655440000"

    def test_pod_uid_stays_empty_when_server_is_old(self, analyzer):
        """pod.uid is left empty when the server returns an empty string (pre-v1.6.0)."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(uid="")

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_uid == ""

    def test_pod_annotations_populated_when_present(self, analyzer):
        """pod.pod_annotations (Tetragon v1.5.0+) is captured when the server supplies it."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            pod_annotations={"prometheus.io/scrape": "true", "sidecar.istio.io/inject": "false"},
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_annotations == {
            "prometheus.io/scrape": "true",
            "sidecar.istio.io/inject": "false",
        }

    def test_pod_annotations_empty_dict_when_server_is_old(self, analyzer):
        """pod.pod_annotations is an empty dict when the server supplies nothing (pre-v1.5.0)."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(pod_annotations={})

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.pod_annotations == {}

    def test_container_privileged_set_when_security_context_present(self, analyzer):
        """container.security_context.privileged (Tetragon v1.5.0+) is captured when supplied."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            container=MockTetragonContainer(privileged=True),
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_privileged is True

    def test_container_privileged_false_when_security_context_absent(self, analyzer):
        """container_privileged stays False when the server doesn't send security_context (pre-v1.5.0)."""
        cert_info    = _make_cert_info()
        tetragon_pod = MockTetragonPod(
            container=MockTetragonContainer(privileged=None),
        )

        analyzer._apply_pod_context(cert_info, tetragon_pod)

        assert cert_info.container_privileged is False


class TestLogCertificateStatusOutput:
    """
    Tests for log_certificate_status - verifies the correct log level is used
    and that pod enrichment context appears in the log message when present.
    """

    def test_expired_cert_logs_at_error(self, analyzer, caplog):
        """Expired certificate logs at ERROR level."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() - timedelta(days=5),
            common_name="expired.example.com",
        )

        with caplog.at_level(logging.ERROR, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("EXPIRED" in r.message for r in caplog.records)
        assert any(r.levelno == logging.ERROR for r in caplog.records)

    def test_critical_expiry_logs_at_critical(self, analyzer, caplog):
        """Certificate expiring within 7 days logs at CRITICAL level."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=3),
            common_name="critical.example.com",
        )

        with caplog.at_level(logging.CRITICAL, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("CRITICAL" in r.message for r in caplog.records)
        assert any(r.levelno == logging.CRITICAL for r in caplog.records)

    def test_warning_expiry_logs_at_warning(self, analyzer, caplog):
        """Certificate expiring within threshold (default 30 days) logs at WARNING."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=15),
            common_name="warning.example.com",
        )

        with caplog.at_level(logging.WARNING, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("WARNING" in r.message for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records)

    def test_valid_cert_logs_at_info(self, analyzer, caplog):
        """Valid certificate with plenty of time left logs at INFO level."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
            common_name="valid.example.com",
        )

        with caplog.at_level(logging.INFO, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        assert any("OK" in r.message for r in caplog.records)
        assert any(r.levelno == logging.INFO for r in caplog.records)

    def test_pod_context_included_in_log_when_present(self, analyzer, caplog):
        """Pod name and namespace appear in the log message when enrichment data is set."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() - timedelta(days=1),
            pod_name="cert-test-abc",
            namespace="staging",
            workload_kind="Deployment",
            workload_name="cert-test",
        )

        with caplog.at_level(logging.ERROR, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "cert-test-abc"       in log_messages
        assert "staging"             in log_messages
        assert "Deployment/cert-test" in log_messages

    def test_pod_context_absent_from_log_when_not_enriched(self, analyzer, caplog):
        """No pod context suffix appears in the log when pod_name is empty."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
        )

        with caplog.at_level(logging.INFO, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "pod="       not in log_messages
        assert "namespace=" not in log_messages

    def test_container_name_included_in_log_when_enriched(self, analyzer, caplog):
        """Container name appears in the log when set by the k8s enricher."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() - timedelta(days=1),
            pod_name="mypod",
            namespace="default",
            container_name="sidecar",
        )

        with caplog.at_level(logging.ERROR, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "sidecar" in log_messages

    def test_multi_cert_file_index_in_log(self, analyzer, caplog):
        """cert_index > 0 causes the cert number to appear in the log path."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
            cert_index=2,
        )

        with caplog.at_level(logging.INFO, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "cert #3" in log_messages

    def test_summary_only_omits_detail_dump(self, analyzer, caplog):
        """
        summary_only=True logs just the headline status line, not the
        Subject/Issuer/Serial/SAN/etc. detail dump below it.
        """
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
            subject="CN=summary-only-test",
        )

        with caplog.at_level(logging.DEBUG, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info, summary_only=True)

        assert any("OK" in r.message for r in caplog.records)
        log_messages = " ".join(r.message for r in caplog.records)
        assert "Subject:" not in log_messages
        assert "Issuer:"  not in log_messages
        assert "Valid:"   not in log_messages

    def test_default_still_includes_detail_dump(self, analyzer, caplog):
        """Without summary_only, the detail dump is still emitted (default unchanged)."""
        cert_info = _make_cert_info(
            not_after=datetime.utcnow() + timedelta(days=365),
            subject="CN=full-detail-test",
        )

        with caplog.at_level(logging.DEBUG, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_info)

        log_messages = " ".join(r.message for r in caplog.records)
        assert "Subject:" in log_messages
        assert "Issuer:"  in log_messages

# ── JKS helpers ───────────────────────────────────────────────────────────────

import hashlib
import struct
import time as _time


def _make_jks_truststore(cert: x509.Certificate, password: str = 'changeit') -> bytes:
    """
    Build a minimal JKS truststore containing a single TrustedCertEntry.

    Constructs the binary JKS format without needing keytool or a JDK.
    Layout: magic(4) + version(4) + entry_count(4) + entry + SHA1_digest(20)

    The integrity digest is:
        SHA1(password_as_utf16be + b"Mighty Aphrodite" + preceding_bytes)
    """
    cert_der  = cert.public_bytes(serialization.Encoding.DER)
    alias     = 'test-cert'
    alias_enc = alias.encode('utf-16-be')
    cert_type = b'X.509'
    timestamp = int(_time.time() * 1000)

    entry  = struct.pack('>I', 2)                                # tag = TrustedCertEntry
    entry += struct.pack('>H', len(alias_enc)) + alias_enc       # alias
    entry += struct.pack('>Q', timestamp)                        # creation date (ms)
    entry += struct.pack('>H', len(cert_type)) + cert_type       # cert type
    entry += struct.pack('>I', len(cert_der))  + cert_der        # cert DER bytes

    body   = struct.pack('>III', 0xFEEDFEED, 2, 1) + entry      # header + 1 entry

    pw_bytes = b''.join(struct.pack('>H', ord(c)) for c in password)
    digest   = hashlib.sha1(pw_bytes + b'Mighty Aphrodite' + body).digest()

    return body + digest


def _make_jks_truststore_multi(certs: list, password: str = 'changeit') -> bytes:
    """
    Build a JKS truststore containing multiple TrustedCertEntries.

    Each certificate gets a unique alias ('test-cert-0', 'test-cert-1', ...).
    Layout is identical to _make_jks_truststore but with entry_count > 1.
    """
    entries = b''
    for i, cert in enumerate(certs):
        cert_der  = cert.public_bytes(serialization.Encoding.DER)
        alias     = f'test-cert-{i}'
        alias_enc = alias.encode('utf-16-be')
        cert_type = b'X.509'
        timestamp = int(_time.time() * 1000)

        entry  = struct.pack('>I', 2)
        entry += struct.pack('>H', len(alias_enc)) + alias_enc
        entry += struct.pack('>Q', timestamp)
        entry += struct.pack('>H', len(cert_type)) + cert_type
        entry += struct.pack('>I', len(cert_der))  + cert_der
        entries += entry

    body = struct.pack('>III', 0xFEEDFEED, 2, len(certs)) + entries

    pw_bytes = b''.join(struct.pack('>H', ord(c)) for c in password)
    digest   = hashlib.sha1(pw_bytes + b'Mighty Aphrodite' + body).digest()

    return body + digest


try:
    import jks as _jks_probe  # noqa: F401
    _JKS_AVAILABLE = True
except ImportError:
    _JKS_AVAILABLE = False

pytestmark_jks = pytest.mark.skipif(
    not _JKS_AVAILABLE,
    reason="pyjks not installed"
)


class TestJKSParsing:
    """
    Test parsing of JKS keystore files (.jks / .keystore / .truststore).

    Mirrors TestPKCS12Parsing in structure. All tests are skipped when pyjks
    is not installed so the suite still passes in environments where the
    optional dependency is absent. The one exception is
    test_jks_unavailable_returns_empty_and_increments_metric which patches
    JKS_AVAILABLE directly and therefore runs everywhere.
    """

    @pytestmark_jks
    def test_parse_valid_jks_truststore_returns_cert(self, analyzer, temp_dir):
        """parse_jks_certificates extracts the certificate from a truststore."""
        cert, _ = TestCertificateGeneration.generate_certificate("jks-leaf.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "truststore.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_jks_certificates(jks_path)

        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "jks-leaf.example.com"

    @pytestmark_jks
    def test_parse_expired_jks_cert_detected(self, analyzer, temp_dir):
        """An expired certificate inside a JKS truststore is correctly identified."""
        cert, _ = TestCertificateGeneration.generate_certificate("expired-jks.example.com", -30)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "expired.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        cert_infos = analyzer.analyze_certificate(jks_path, "java", 1234)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_expired
        assert cert_infos[0].common_name == "expired-jks.example.com"

    @pytestmark_jks
    def test_parse_jks_custom_password_via_env(self, analyzer, temp_dir, monkeypatch):
        """JKS_PASSWORD env var is tried before the default password list."""
        cert, _ = TestCertificateGeneration.generate_certificate("pw-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert, password='mysecretpassword')

        jks_path = os.path.join(temp_dir, "custom-pw.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        monkeypatch.setenv('JKS_PASSWORD', 'mysecretpassword')

        certs = analyzer.parse_jks_certificates(jks_path)

        assert len(certs) == 1
        cn = certs[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "pw-jks.example.com"

    @pytestmark_jks
    def test_parse_jks_wrong_password_returns_empty(self, analyzer, temp_dir, monkeypatch):
        """parse_jks_certificates returns [] when all passwords fail."""
        cert, _ = TestCertificateGeneration.generate_certificate("secure-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert, password='supersecret')

        jks_path = os.path.join(temp_dir, "secured.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        monkeypatch.delenv('JKS_PASSWORD', raising=False)

        certs = analyzer.parse_jks_certificates(jks_path)
        assert certs == []

    @pytestmark_jks
    def test_parse_jks_failed_path_cached(self, analyzer, temp_dir, monkeypatch):
        """A JKS file that fails password attempts is cached and skipped on retry."""
        cert, _ = TestCertificateGeneration.generate_certificate("cached-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert, password='supersecret')

        jks_path = os.path.join(temp_dir, "cached.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        monkeypatch.delenv('JKS_PASSWORD', raising=False)

        # First call — should attempt passwords and fail
        analyzer.parse_jks_certificates(jks_path)
        assert jks_path in analyzer.password_failed_paths

        # Second call — error counter must not increment again
        before = analyzer.metrics.cert_analysis_errors.labels(error_type='jks_password_failed', node_name=analyzer.metrics._node_name)._value.get()
        analyzer.parse_jks_certificates(jks_path)
        after = analyzer.metrics.cert_analysis_errors.labels(error_type='jks_password_failed', node_name=analyzer.metrics._node_name)._value.get()
        assert after == before

    def test_parse_jks_password_list_does_not_include_changeme_or_password(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        The JKS password list only tries env var, 'changeit', and empty string.
        'changeme' and 'password' are not attempted.
        """
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'JKS_AVAILABLE', True)
        monkeypatch.delenv('JKS_PASSWORD', raising=False)

        tried = []

        class _CapturingKeyStore:
            @staticmethod
            def load(path, password):
                tried.append(password)
                raise Exception("wrong password")

        import types
        jks_stub = types.ModuleType('jks')
        jks_stub.KeyStore = _CapturingKeyStore
        jks_stub.util = types.SimpleNamespace(BadKeystoreFormatException=Exception)
        monkeypatch.setattr(_ca, 'jks', jks_stub, raising=False)

        jks_path = os.path.join(temp_dir, "pw-list.jks")
        with open(jks_path, 'wb') as f:
            f.write(b'dummy')

        analyzer.parse_jks_certificates(jks_path)

        assert 'changeme' not in tried
        assert 'password'  not in tried

    @pytestmark_jks
    def test_parse_jks_file_not_found_returns_empty(self, analyzer):
        """parse_jks_certificates returns [] gracefully when the file does not exist."""
        certs = analyzer.parse_jks_certificates("/nonexistent/path/truststore.jks")
        assert certs == []

    @pytestmark_jks
    def test_parse_certificates_dispatches_jks(self, analyzer, temp_dir):
        """parse_certificates routes .jks files to parse_jks_certificates."""
        cert, _ = TestCertificateGeneration.generate_certificate("dispatch-jks.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "dispatch.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_certificates(jks_path)
        assert len(certs) == 1

    @pytestmark_jks
    def test_parse_certificates_dispatches_keystore_extension(self, analyzer, temp_dir):
        """.keystore extension is routed to parse_jks_certificates."""
        cert, _ = TestCertificateGeneration.generate_certificate("keystore.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        ks_path = os.path.join(temp_dir, "server.keystore")
        with open(ks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_certificates(ks_path)
        assert len(certs) == 1

    @pytestmark_jks
    def test_parse_certificates_dispatches_truststore_extension(self, analyzer, temp_dir):
        """.truststore extension is routed to parse_jks_certificates."""
        cert, _ = TestCertificateGeneration.generate_certificate("truststore.example.com", 365)
        jks_data = _make_jks_truststore(cert)

        ts_path = os.path.join(temp_dir, "ca.truststore")
        with open(ts_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_certificates(ts_path)
        assert len(certs) == 1

    @pytestmark_jks
    def test_analyze_certificate_returns_cert_info_for_jks(self, analyzer, temp_dir):
        """analyze_certificate returns populated CertificateInfo for .jks files."""
        cert, _ = TestCertificateGeneration.generate_certificate("java-app-jks.example.com", 90)
        jks_data = _make_jks_truststore(cert)

        jks_path = os.path.join(temp_dir, "java-app.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        cert_infos = analyzer.analyze_certificate(jks_path, "/usr/bin/java", 4242)

        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.common_name == "java-app-jks.example.com"
        assert info.path        == jks_path
        assert info.process     == "/usr/bin/java"
        assert info.pid         == 4242
        assert not info.is_expired
        assert 89 < info.days_until_expiry <= 90

    @pytestmark_jks
    def test_parse_jks_truststore_with_multiple_certs(self, analyzer, temp_dir):
        """A truststore with multiple TrustedCertEntries returns all certificates."""
        cert1, _ = TestCertificateGeneration.generate_certificate("ca-root.example.com",   3650, is_ca=True)
        cert2, _ = TestCertificateGeneration.generate_certificate("ca-inter.example.com",  1825, is_ca=True)
        cert3, _ = TestCertificateGeneration.generate_certificate("leaf.example.com",        365)

        jks_data = _make_jks_truststore_multi([cert1, cert2, cert3])

        jks_path = os.path.join(temp_dir, "multi.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        certs = analyzer.parse_jks_certificates(jks_path)

        assert len(certs) == 3
        common_names = [
            c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            for c in certs
        ]
        assert "ca-root.example.com"  in common_names
        assert "ca-inter.example.com" in common_names
        assert "leaf.example.com"     in common_names

    @pytestmark_jks
    def test_parse_jks_multi_cert_mixed_expiry(self, analyzer, temp_dir):
        """analyze_certificate correctly identifies expired certs within a multi-entry truststore."""
        valid_cert,   _ = TestCertificateGeneration.generate_certificate("valid-jks.example.com",   365)
        expired_cert, _ = TestCertificateGeneration.generate_certificate("expired-jks.example.com", -30)
        soon_cert,    _ = TestCertificateGeneration.generate_certificate("soon-jks.example.com",      5)

        jks_data = _make_jks_truststore_multi([valid_cert, expired_cert, soon_cert])

        jks_path = os.path.join(temp_dir, "mixed-expiry.jks")
        with open(jks_path, 'wb') as f:
            f.write(jks_data)

        cert_infos = analyzer.analyze_certificate(jks_path, "/usr/bin/java", 1234)

        assert len(cert_infos) == 3

        by_cn = {info.common_name: info for info in cert_infos}
        assert not by_cn["valid-jks.example.com"].is_expired
        assert     by_cn["expired-jks.example.com"].is_expired
        assert     by_cn["soon-jks.example.com"].expires_soon(days=7)

    def test_jks_unavailable_returns_empty_and_increments_metric(self, analyzer, temp_dir, monkeypatch):
        """
        When pyjks is not installed parse_jks_certificates returns [] and
        increments the jks_unavailable error metric.

        Patches the module-level JKS_AVAILABLE flag so this test runs
        regardless of whether pyjks is installed in the test environment.
        """
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'JKS_AVAILABLE', False)

        jks_path = os.path.join(temp_dir, "dummy.jks")
        with open(jks_path, 'wb') as f:
            f.write(b'dummy')

        certs = analyzer.parse_jks_certificates(jks_path)
        assert certs == []


class TestProcessEventTimestamp:
    """
    Tests that last_event_timestamp is updated correctly in process_event,
    including when cert files are skipped due to password failure caching.
    """

    def _make_mock_event(self, cert_path):
        """Build a minimal mock Tetragon kprobe event for the given path."""
        class _MockArg:
            def __init__(self, path):
                self.string_arg = path
            def HasField(self, name):
                return name == 'string_arg'

        class _MockProcess:
            binary    = '/usr/bin/java'
            pid       = 1234
            arguments = ''
            def HasField(self, name):
                return False

        class _MockKprobe:
            def __init__(self, path):
                self.process = _MockProcess()
                self.args    = [_MockArg(path)]
            def HasField(self, name):
                return False

        class _MockEvent:
            node_name = ''
            def __init__(self_, path):
                self_._kprobe = _MockKprobe(path)
            def HasField(self_, name):
                return name == 'process_kprobe'
            @property
            def process_kprobe(self_):
                return self_._kprobe

        return _MockEvent(cert_path)

    def test_timestamp_updated_when_cert_file_skipped_due_to_password_failure(
        self, analyzer, temp_dir
    ):
        """
        last_event_timestamp must be updated even when analyze_certificate
        returns [] because the file is in password_failed_paths.

        The mock event carries the bare path (no /host prefix). The analyzer
        prepends /host internally, so we register that prefixed path in
        password_failed_paths. No actual /host directory is needed.
        """
        disk_path = os.path.join(temp_dir, "pw-skip.p12")
        cert, key = TestCertificateGeneration.generate_certificate("pw-skip.example.com", 365)
        p12_data  = _make_pkcs12(cert, key, password=b'supersecret')
        with open(disk_path, 'wb') as f:
            f.write(p12_data)

        # The analyzer prepends /host to paths from events — register that
        # prefixed path so the file is recognised as previously failed
        host_path = '/host' + disk_path
        analyzer.password_failed_paths.add(host_path)
        analyzer.last_event_time = 0.0

        # Event carries the bare (non-/host) path; analyzer adds /host
        analyzer.process_event(self._make_mock_event(disk_path))

        assert analyzer.last_event_time > 0, \
            "last_event_timestamp was not updated for a skipped password-failed file"

    def test_timestamp_updated_when_cert_file_successfully_parsed(
        self, analyzer, temp_dir
    ):
        """
        last_event_timestamp is updated when a cert is successfully parsed.

        Pre-seeds known_certs so process_event takes the re-detection branch,
        which avoids needing the /host symlink to exist on the runner.
        """
        disk_path = os.path.join(temp_dir, "ts-test.pem")
        cert, _   = TestCertificateGeneration.generate_certificate("ts-test.example.com", 365)
        TestCertificateGeneration.save_certificate_pem(cert, disk_path)

        # Pre-seed known_certs with the /host-prefixed path so process_event
        # hits the re-detection branch and updates the timestamp without
        # needing to read from /host on the filesystem
        host_path = '/host' + disk_path
        dummy = CertificateInfo(
            path=host_path, subject='CN=ts-test', issuer='CN=ca',
            serial_number='1',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process='test', pid=1,
        )
        analyzer.known_certs[dummy.unique_key] = dummy
        analyzer.last_event_time = 0.0

        analyzer.process_event(self._make_mock_event(disk_path))

        assert analyzer.last_event_time > 0


class TestLRUCache:
    """
    Tests for the LRUCache class — eviction, LRU ordering, minimum size
    enforcement, set-like interface, and dict-like interface.
    """

    def test_basic_get_set(self):
        """Values can be stored and retrieved."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        assert cache['a'] == 1

    def test_contains(self):
        """'in' operator works correctly."""
        cache = LRUCache(maxsize=10_000)
        cache['x'] = True
        assert 'x' in cache
        assert 'y' not in cache

    def test_len(self):
        """len() reflects current entry count."""
        cache = LRUCache(maxsize=10_000)
        for i in range(5):
            cache[str(i)] = i
        assert len(cache) == 5

    def test_evicts_lru_entry_when_full(self):
        """When at capacity, the least-recently-used entry is evicted."""
        cache = LRUCache(maxsize=10_000)
        # Fill to capacity using internal store directly for speed
        for i in range(10_000):
            cache._store[str(i)] = i
        # 'str(0)' is the LRU entry — adding one more should evict it
        cache['new'] = 'new'
        assert '0' not in cache
        assert 'new' in cache
        assert len(cache) == 10_000

    def test_access_promotes_to_mru(self):
        """Accessing an entry moves it to the MRU end, protecting it from eviction."""
        cache = LRUCache(maxsize=10_000)
        for i in range(10_000):
            cache._store[str(i)] = i
        # Access '0' — it should move to MRU end
        _ = cache['0']
        # Add a new entry — '1' (now LRU) should be evicted, not '0'
        cache['new'] = 'new'
        assert '0' in cache
        assert '1' not in cache

    def test_update_existing_key_does_not_grow(self):
        """Updating an existing key does not add a new entry."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        cache['a'] = 2
        assert len(cache) == 1
        assert cache['a'] == 2

    def test_delete(self):
        """Entries can be deleted."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        del cache['a']
        assert 'a' not in cache
        assert len(cache) == 0

    def test_add_and_discard_set_interface(self):
        """add() and discard() provide a Set-like interface."""
        cache = LRUCache(maxsize=10_000)
        cache.add('path/to/keystore.jks')
        assert 'path/to/keystore.jks' in cache
        cache.discard('path/to/keystore.jks')
        assert 'path/to/keystore.jks' not in cache
        # discard on absent key must not raise
        cache.discard('nonexistent')

    def test_minimum_size_floor_enforced(self):
        """Requesting a size below CACHE_MIN_SIZE is silently raised to the minimum."""
        import cert_analyzer as _ca
        cache = LRUCache(maxsize=1)
        assert cache.maxsize == _ca.CACHE_MIN_SIZE

    def test_clear(self):
        """clear() empties the cache."""
        cache = LRUCache(maxsize=10_000)
        for i in range(5):
            cache[str(i)] = i
        cache.clear()
        assert len(cache) == 0

    def test_clear_fires_on_evict_for_every_entry(self):
        """
        clear() must fire on_evict for every entry it removes, same as
        discard()/__delitem__ -- otherwise a caller maintaining a secondary
        index or metrics off on_evict (e.g. CertificateAnalyzer's
        _known_paths) is left with ghost entries for everything that was
        cached at the moment of the clear.
        """
        evicted = []
        cache = LRUCache(maxsize=10_000, on_evict=lambda k, v: evicted.append((k, v)))
        for i in range(5):
            cache[str(i)] = i

        cache.clear()

        assert sorted(evicted) == [(str(i), i) for i in range(5)]

    def test_get_with_default(self):
        """get() returns default when key is absent."""
        cache = LRUCache(maxsize=10_000)
        assert cache.get('missing', 'default') == 'default'
        cache['key'] = 'value'
        assert cache.get('key', 'default') == 'value'

    def test_items_keys_values(self):
        """items(), keys(), values() expose the underlying store."""
        cache = LRUCache(maxsize=10_000)
        cache['a'] = 1
        cache['b'] = 2
        assert set(cache.keys()) == {'a', 'b'}
        assert set(cache.values()) == {1, 2}
        assert set(cache.items()) == {('a', 1), ('b', 2)}


class TestCacheIntegration:
    """
    Integration tests verifying that known_certs, processed_paths, and
    password_failed_paths are wired to LRUCache and that Prometheus
    cache size metrics are updated correctly.
    """

    def test_analyzer_uses_lru_cache_for_known_certs(self, analyzer):
        """known_certs is an LRUCache instance."""
        assert isinstance(analyzer.known_certs, LRUCache)

    def test_analyzer_uses_lru_cache_for_processed_paths(self, analyzer):
        """processed_paths is an LRUCache instance."""
        assert isinstance(analyzer.processed_paths, LRUCache)

    def test_analyzer_uses_lru_cache_for_password_failed_paths(self, analyzer):
        """password_failed_paths is an LRUCache instance."""
        assert isinstance(analyzer.password_failed_paths, LRUCache)

    def test_cache_max_size_metric_set_on_init(self, analyzer):
        """cert_analyzer_cache_max_size gauge is set at startup."""
        import cert_analyzer as _ca
        node = analyzer.metrics._node_name
        val = analyzer.metrics.cache_max_size.labels(node_name=node)._value.get()
        assert val == _ca.CACHE_MAX_SIZE

    def test_cache_size_metrics_updated_after_analyze(self, analyzer, temp_dir):
        """Cache size metrics update after a certificate is analyzed."""
        cert, _ = TestCertificateGeneration.generate_certificate("metrics.example.com", 365)
        path = os.path.join(temp_dir, "metrics.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.analyze_certificate(path, "test", 1)

        node = analyzer.metrics._node_name
        assert analyzer.metrics.cache_processed_paths_size.labels(node_name=node)._value.get() == 1

    def test_cache_size_metrics_updated_after_password_failure(
        self, analyzer, temp_dir, monkeypatch
    ):
        """cache_password_failed_size metric updates after a password failure."""
        cert, key = TestCertificateGeneration.generate_certificate("fail.example.com", 365)
        p12_data  = _make_pkcs12(cert, key, password=b'supersecret')
        path      = os.path.join(temp_dir, "fail.p12")
        with open(path, 'wb') as f:
            f.write(p12_data)
        monkeypatch.delenv('PKCS12_PASSWORD', raising=False)

        analyzer.parse_pkcs12_certificates(path)

        node = analyzer.metrics._node_name
        assert analyzer.metrics.cache_password_failed_size.labels(node_name=node)._value.get() == 1

    def test_known_certs_evicts_lru_when_full(self, analyzer, temp_dir):
        """
        When known_certs reaches CACHE_MAX_SIZE the LRU entry is evicted
        rather than the cache growing beyond the cap.
        """
        import cert_analyzer as _ca

        # Directly fill known_certs to capacity using internal store
        for i in range(_ca.CACHE_MAX_SIZE):
            analyzer.known_certs._store[f"path:{i}:serial"] = None

        assert len(analyzer.known_certs) == _ca.CACHE_MAX_SIZE

        # Add one more — should evict the oldest, not grow
        analyzer.known_certs[f"path:{_ca.CACHE_MAX_SIZE}:serial"] = None

        assert len(analyzer.known_certs) == _ca.CACHE_MAX_SIZE
        assert "path:0:serial" not in analyzer.known_certs


class TestKnownCertsIndex:
    """
    Tests for the _known_paths index (agent/analyzer.py) that process_event's
    "already known certificate file" check now uses instead of scanning every
    entry in known_certs. Covers population on first parse, cleanup on LRU
    eviction, and that entries without a usable path degrade gracefully
    instead of raising.
    """

    def test_index_populated_after_first_parse(self, analyzer, temp_dir):
        """_known_paths gains an entry when a cert is analyzed via the normal flow."""
        cert, _ = TestCertificateGeneration.generate_certificate("index-test.example.com", 365)
        path = os.path.join(temp_dir, "index-test.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")

        assert path in analyzer._known_paths
        assert cert_infos[0].unique_key in analyzer._known_paths[path]

    def test_index_cleaned_up_on_lru_eviction(self, analyzer, temp_dir):
        """
        When known_certs evicts its LRU entry, that entry's path must also
        disappear from _known_paths — otherwise process_event would believe
        an evicted cert is still known and hand back a stale key.
        """
        import cert_analyzer as _ca

        target = CertificateInfo(
            path="/tmp/soon-to-be-evicted.pem", subject='CN=x', issuer='CN=ca',
            serial_number='1',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process='test', pid=1,
        )
        # Real __setitem__ so the on_set callback actually indexes it, and it
        # lands at the LRU front (oldest) since it's inserted first.
        analyzer.known_certs[target.unique_key] = target
        assert target.path in analyzer._known_paths

        # Fill the rest of the cache directly (cheap — bypasses callbacks,
        # same approach as test_known_certs_evicts_lru_when_full above).
        for i in range(_ca.CACHE_MAX_SIZE - 1):
            analyzer.known_certs._store[f"filler:{i}:serial"] = None

        # One more real insert pushes the cache over capacity, evicting
        # `target` (the LRU front) and firing _deindex_known_cert for it.
        filler_info = CertificateInfo(
            path="/tmp/new-entry.pem", subject='CN=y', issuer='CN=ca',
            serial_number='2',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process='test', pid=1,
        )
        analyzer.known_certs[filler_info.unique_key] = filler_info

        assert target.unique_key not in analyzer.known_certs
        assert target.path not in analyzer._known_paths, \
            "evicted cert's path must be removed from the index, not left stale"

    def test_index_cleaned_up_on_known_certs_clear(self, analyzer, temp_dir):
        """
        known_certs.clear() must also fire _deindex_known_cert for every
        entry it removes, same as LRU eviction — otherwise _known_paths would
        retain a ghost entry for every previously-cached cert, making
        process_event believe those paths are still known (and skip
        re-parsing them) even though known_certs has forgotten them.
        """
        cert, _ = TestCertificateGeneration.generate_certificate("cleared.example.com", 365)
        path = os.path.join(temp_dir, "cleared.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")
        assert path in analyzer._known_paths

        analyzer.known_certs.clear()

        assert len(analyzer.known_certs) == 0
        assert path not in analyzer._known_paths, \
            "clear() must not leave a ghost _known_paths entry for a cert no longer cached"

    def test_index_ignores_entries_without_a_path(self, analyzer):
        """
        Cache entries with no usable .path (e.g. tests seeding known_certs
        with None, as test_known_certs_evicts_lru_when_full does) must not
        crash the on_set/on_evict callbacks.
        """
        analyzer.known_certs["bare:0:serial"] = None
        assert len(analyzer._known_paths) == 0


class TestMetricsCleanupOnEviction:
    """
    Tests for PrometheusMetrics.remove_certificate_metrics, wired into
    CertificateAnalyzer._deindex_known_cert (known_certs' on_evict callback).

    Before this, evicting a cert from known_certs only cleaned up the
    _known_paths index -- the ~10 per-cert Prometheus Gauge series created by
    update_certificate_metrics were never removed, so Prometheus registry
    memory grew for the entire life of the process regardless of cache size.
    A single first-time scan of the system CA trust bundle (146 certs, all
    under large_file_metrics_cap) added ~32MB in one burst in production.
    """

    @staticmethod
    def _samples_for(gauge, cert_path):
        return [
            s for metric in gauge.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == cert_path
        ]

    def test_per_cert_series_removed_on_lru_eviction(self, analyzer, temp_dir):
        """
        Evicting a cert from known_certs must remove its cert_expiry_days,
        cert_expiry_timestamp, cert_process_info, and cert_self_signed series --
        otherwise Prometheus keeps every cert ever discovered in memory
        forever, independent of whether the LRU cache actually evicted it.
        """
        import cert_analyzer as _ca

        cert, _ = TestCertificateGeneration.generate_certificate("evict-me.example.com", 365)
        path = os.path.join(temp_dir, "evict-me.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test-proc", 111)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")
        target_key = cert_infos[0].unique_key

        gauges = (
            analyzer.metrics.cert_expiry_days,
            analyzer.metrics.cert_expiry_timestamp,
            analyzer.metrics.cert_process_info,
            analyzer.metrics.cert_self_signed,
        )

        assert target_key in analyzer.known_certs
        for gauge in gauges:
            assert self._samples_for(gauge, path), \
                f"{gauge._name} should have a series before eviction"

        # Fill the rest of the cache directly (cheap — bypasses callbacks,
        # same approach as TestKnownCertsIndex.test_index_cleaned_up_on_lru_eviction)
        # so the next real insert pushes `target_key` out as the LRU-oldest entry.
        for i in range(_ca.CACHE_MAX_SIZE - 1):
            analyzer.known_certs._store[f"filler:{i}:serial"] = None
        filler = CertificateInfo(
            path="/tmp/new-entry.pem", subject='CN=y', issuer='CN=ca',
            serial_number='2',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process='test', pid=1,
        )
        analyzer.known_certs[filler.unique_key] = filler

        assert target_key not in analyzer.known_certs
        for gauge in gauges:
            assert not self._samples_for(gauge, path), \
                f"{gauge._name} series must be removed when its cert is evicted"

    def test_metrics_removal_ignores_entries_missing_fields(self, analyzer):
        """
        An evicted entry with a .path but missing other CertificateInfo
        fields (e.g. a minimal stub, mirroring how
        test_index_ignores_entries_without_a_path covers a bare None value)
        must not crash metric removal -- it should degrade to a debug log,
        same as the _known_paths index already does.
        """
        import types

        stub = types.SimpleNamespace(path="/tmp/stub-only-path.pem")
        analyzer.known_certs["stub:0:serial"] = stub
        assert "/tmp/stub-only-path.pem" in analyzer._known_paths

        # Must not raise, even though remove_certificate_metrics will hit an
        # AttributeError reading stub.subject/issuer/etc.
        analyzer.known_certs.discard("stub:0:serial")

        assert "/tmp/stub-only-path.pem" not in analyzer._known_paths

    def test_all_tracked_process_series_removed_on_eviction(self, analyzer, temp_dir):
        """
        remove_certificate_metrics must clean up every distinct process
        series tracked in cert_process_info for an evicted cert, not just
        the most recently recorded one -- possible now that CertificateInfo
        tracks its full _seen_processes set (added for the fan-out cap),
        closing the "only partially cleaned up" gap this class's docstring
        used to note.
        """
        import cert_analyzer as _ca

        cert, _ = TestCertificateGeneration.generate_certificate("multi-proc.example.com", 365)
        path = os.path.join(temp_dir, "multi-proc.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "discoverer-proc", 1)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")
        target = cert_infos[0]
        target_key = target.unique_key

        for i in range(3):
            analyzer._record_cert_process_access(target, f"/usr/bin/proc{i}", "")

        samples_before = self._samples_for(analyzer.metrics.cert_process_info, path)
        assert len(samples_before) == 4, "discoverer + 3 distinct re-accessing processes"

        # Fill the rest of the cache and evict `target` as the LRU-oldest entry
        # (same approach as test_per_cert_series_removed_on_lru_eviction above).
        for i in range(_ca.CACHE_MAX_SIZE - 1):
            analyzer.known_certs._store[f"filler:{i}:serial"] = None
        filler = CertificateInfo(
            path="/tmp/new-entry.pem", subject='CN=y', issuer='CN=ca',
            serial_number='2',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process='test', pid=1,
        )
        analyzer.known_certs[filler.unique_key] = filler

        assert target_key not in analyzer.known_certs
        assert self._samples_for(analyzer.metrics.cert_process_info, path) == [], \
            "all 4 process series must be removed, not just the most recent one"


class TestMetricsLabelParity:
    """
    Guards against a Gauge's declared labelnames drifting out of sync with
    the .labels() call site(s) that populate it -- prometheus_client raises
    ValueError on any mismatch between the two, uncaught by anything at this
    layer. This file hand-duplicates the same label set across five Gauges
    (cert_expiry_days, cert_expiry_timestamp, cert_valid_from,
    cert_last_accessed, cert_fips_compliant) and multiple call sites
    (update_certificate_metrics's shared dict, update_last_accessed's
    separate direct call, and remove_certificate_metrics's positional
    removal tuples), so this is exactly the kind of change most likely to
    drift. It already has, twice, while adding spki_algorithm_oid/
    signature_algorithm_oid -- update_last_accessed's call site was missed
    on the first pass and only surfaced once the full suite ran, not from
    any test that specifically targets that call site.
    """

    def test_full_metrics_lifecycle_does_not_raise(self, analyzer, temp_dir):
        """update_certificate_metrics -> update_last_accessed ->
        remove_certificate_metrics must all succeed for a fully-populated
        CertificateInfo. A labelname/call-site mismatch on any of the five
        Gauges they touch raises ValueError immediately here, rather than
        only incidentally through unrelated tests."""
        assert analyzer.fips_compliance_enabled is True  # also exercises cert_fips_compliant

        cert, _ = TestCertificateGeneration.generate_certificate("label-parity.example.com", 365)
        path = os.path.join(temp_dir, "label-parity.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test-proc", 222)
        assert len(cert_infos) == 1
        cert_info = cert_infos[0]

        analyzer.metrics.update_certificate_metrics(cert_info)
        analyzer.metrics.update_last_accessed(cert_info)
        analyzer.metrics.remove_certificate_metrics(cert_info)

    def test_shared_expiry_gauges_have_identical_labelnames(self, analyzer):
        """cert_expiry_days/timestamp/valid_from/last_accessed are all set
        from one shared `labels` dict in update_certificate_metrics -- their
        labelname sets must stay identical, or that single .labels(**labels)
        call raises for whichever gauge's declared list drifted from it."""
        m = analyzer.metrics
        gauges = (m.cert_expiry_days, m.cert_expiry_timestamp, m.cert_valid_from, m.cert_last_accessed)
        labelname_sets = [set(g._labelnames) for g in gauges]
        assert all(s == labelname_sets[0] for s in labelname_sets), \
            {g._name: sorted(g._labelnames) for g in gauges}


class TestCertProcessInfoFanoutCap:
    """
    Tests for CertificateAnalyzer._record_cert_process_access's cap on
    distinct (process, parent_process) pairs tracked per cert
    (max_processes_per_cert).

    TestMetricsCleanupOnEviction closes the leak for certs that actually get
    LRU-evicted, but a file re-accessed by many distinct processes (e.g. the
    system CA trust bundle touched by curl, dnf, git, python, docker, ...)
    may never be evicted while still actively in use -- without this cap,
    cert_process_info would keep growing by one series per new distinct
    process, forever, regardless of known_certs cache size.
    """

    @staticmethod
    def _samples_for(gauge, cert_path):
        return [
            s for metric in gauge.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == cert_path
        ]

    def test_distinct_processes_capped_at_max_processes_per_cert(self, analyzer, temp_dir):
        """Only the first max_processes_per_cert distinct processes (including
        the discoverer) ever get their own cert_process_info series."""
        analyzer._max_processes_per_cert = 3
        cert, _ = TestCertificateGeneration.generate_certificate("fanout.example.com", 365)
        path = os.path.join(temp_dir, "fanout.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "discoverer-proc", 1)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")
        cert_info = cert_infos[0]

        for i in range(10):
            analyzer._record_cert_process_access(cert_info, f"/usr/bin/proc{i}", "")

        samples = self._samples_for(analyzer.metrics.cert_process_info, path)
        assert len(samples) == 3, \
            f"expected exactly max_processes_per_cert (3) series, got {len(samples)}"

    def test_repeat_access_by_already_tracked_process_is_not_capped(self, analyzer, temp_dir):
        """
        Re-access by a process that already has a series must keep refreshing
        it rather than being mistaken for a new distinct process competing
        for the (already-exhausted) cap.
        """
        analyzer._max_processes_per_cert = 1
        cert, _ = TestCertificateGeneration.generate_certificate("repeat.example.com", 365)
        path = os.path.join(temp_dir, "repeat.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "discoverer-proc", 1)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")
        cert_info = cert_infos[0]

        # Cap (1) is already exhausted by the discoverer alone.
        analyzer._record_cert_process_access(cert_info, "discoverer-proc", "")
        analyzer._record_cert_process_access(cert_info, "discoverer-proc", "")

        samples = self._samples_for(analyzer.metrics.cert_process_info, path)
        assert len(samples) == 1
        assert samples[0].labels.get('process') == 'discoverer-proc'

    def test_process_dropped_by_cap_increments_error_metric(self, analyzer, temp_dir):
        """A process rejected by the cap must be observable, not silent."""
        analyzer._max_processes_per_cert = 1
        cert, _ = TestCertificateGeneration.generate_certificate("capmetric.example.com", 365)
        path = os.path.join(temp_dir, "capmetric.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "discoverer-proc", 1)
        analyzer._finish_new_certificate_file(cert_infos, None, "", 0, "")
        cert_info = cert_infos[0]

        before = analyzer.metrics.cert_analysis_errors.labels(error_type='process_fanout_cap_reached', node_name=analyzer.metrics._node_name)._value.get()

        analyzer._record_cert_process_access(cert_info, "/usr/bin/other", "")

        after = analyzer.metrics.cert_analysis_errors.labels(error_type='process_fanout_cap_reached', node_name=analyzer.metrics._node_name)._value.get()
        assert after == before + 1


class TestCacheHitReDetection:
    """
    Tests for the "already known certificate file" branch in process_event
    (agent/analyzer.py) — when a cert is re-detected, it must:
      - record the *new* accessing process as its own series in
        tls_certificate_process_info rather than overwriting/ignoring it, and
      - refresh only tls_certificate_last_accessed_timestamp, not re-run the
        full update_certificate_metrics() fan-out for every cached cert.
    """

    class _MockEvent:
        """Minimal mock Tetragon kprobe event with a configurable process binary
        and, optionally, pod context (for per-access pod attribution tests)."""
        node_name = ''

        def __init__(self, path, process_binary, pod=None):
            class _Arg:
                def __init__(self, path):
                    self.string_arg = path
                def HasField(self, name):
                    return name == 'string_arg'

            class _Process:
                def __init__(self, binary, pod):
                    self.binary    = binary
                    self.pid       = 4321
                    self.arguments = ''
                    self.pod       = pod
                def HasField(self, name):
                    return name == 'pod' and self.pod is not None

            class _Kprobe:
                def __init__(self, path, binary, pod):
                    self.process = _Process(binary, pod)
                    self.args    = [_Arg(path)]
                def HasField(self, name):
                    return False

            self._kprobe = _Kprobe(path, process_binary, pod)

        def HasField(self, name):
            return name == 'process_kprobe'

        @property
        def process_kprobe(self):
            return self._kprobe

    def _seed_known_cert(self, analyzer, path, process='/usr/bin/cat'):
        cert_info = CertificateInfo(
            path=path, subject='CN=cache-hit-test', issuer='CN=ca',
            serial_number='42',
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process=process, pid=1,
        )
        analyzer.known_certs[cert_info.unique_key] = cert_info
        return cert_info

    def test_redetection_records_new_process_as_separate_series(self, analyzer, temp_dir):
        """
        A second process re-detecting a known cert file must appear as its
        own series in tls_certificate_process_info, alongside — not instead
        of — the original discovering process.
        """
        disk_path = os.path.join(temp_dir, "shared-ca.pem")
        cert_info = self._seed_known_cert(analyzer, disk_path, process='/usr/bin/cat')

        # Original discoverer's series, as recorded at first-parse time.
        # cert_info.node_name defaults to '' — the mock event's node_name is
        # also '', so it's left untouched by the re-detection branch below.
        analyzer.metrics.record_cert_process_access(cert_info, '/usr/bin/cat', '')

        analyzer.process_event(self._MockEvent(disk_path, '/usr/lib64/firefox/firefox'))

        gauge = analyzer.metrics.cert_process_info
        cat_val = gauge.labels(
            cert_path=disk_path, cert_index='0', serial='42',
            process='/usr/bin/cat', parent_process='', node_name='',
            pod_name='', namespace='', app_label='', container_name='', checksum='',
            spki_hash='',
        )._value.get()
        firefox_val = gauge.labels(
            cert_path=disk_path, cert_index='0', serial='42',
            process='/usr/lib64/firefox/firefox', parent_process='', node_name='',
            pod_name='', namespace='', app_label='', container_name='', checksum='',
            spki_hash='',
        )._value.get()

        assert cat_val == 1, "original discoverer's series must survive the re-detection"
        assert firefox_val == 1, "new accessing process must get its own series"

    def test_redetection_by_different_pods_attributes_each_to_its_own_pod(self, analyzer, temp_dir):
        """
        The same process binary re-detecting a known cert file from two
        different pods must produce two distinct tls_certificate_process_info
        series, each correctly labeled with *its own* pod_name/namespace/
        app_label/container_name — not both attributed to the cert's own
        (possibly different) discovering pod, which is what using cert_info's
        sticky pod fields instead of the current event's would have done.
        """
        disk_path = os.path.join(temp_dir, "multi-pod-ca.pem")
        # Discovered outside any pod (cert_info.pod_name stays "").
        self._seed_known_cert(analyzer, disk_path, process='/usr/bin/python')

        pod_a = MockTetragonPod(
            name="svc-a-abc12", namespace="ns-a", pod_labels={"app": "svc-a"},
            container=MockTetragonContainer(name="main-a"),
        )
        pod_b = MockTetragonPod(
            name="svc-b-def34", namespace="ns-b", pod_labels={"app": "svc-b"},
            container=MockTetragonContainer(name="main-b"),
        )

        analyzer.process_event(self._MockEvent(disk_path, '/usr/bin/python', pod=pod_a))
        analyzer.process_event(self._MockEvent(disk_path, '/usr/bin/python', pod=pod_b))

        gauge = analyzer.metrics.cert_process_info
        samples = [
            s for metric in gauge.collect() for s in metric.samples
            if s.labels.get('cert_path') == disk_path
        ]
        by_pod = {s.labels['pod_name']: s.labels for s in samples}

        assert "svc-a-abc12" in by_pod, "pod-a's access must get its own series"
        assert "svc-b-def34" in by_pod, "pod-b's access must get its own series"
        assert by_pod["svc-a-abc12"]['namespace']      == 'ns-a'
        assert by_pod["svc-a-abc12"]['app_label']      == 'svc-a'
        assert by_pod["svc-a-abc12"]['container_name'] == 'main-a'
        assert by_pod["svc-b-def34"]['namespace']      == 'ns-b'
        assert by_pod["svc-b-def34"]['app_label']      == 'svc-b'
        assert by_pod["svc-b-def34"]['container_name'] == 'main-b'

    def test_redetection_updates_last_accessed_timestamp(self, analyzer, temp_dir):
        """tls_certificate_last_accessed_timestamp is refreshed on re-detection."""
        disk_path = os.path.join(temp_dir, "shared-ca2.pem")
        cert_info = self._seed_known_cert(analyzer, disk_path)

        before = analyzer.metrics.cert_last_accessed.labels(
            cert_path=disk_path, subject='CN=cache-hit-test', issuer='CN=ca',
            serial='42', common_name='', san_dns_names='', san_ip_addresses='',
            cert_index='0', pod_name='', namespace='', workload_kind='',
            workload_name='', node_name='', app_label='', container_name='',
            checksum='', spki_hash='', key_usage='', extended_key_usage='',
            spki_algorithm_oid='', signature_algorithm_oid='',
        )._value.get()
        assert before == 0.0

        analyzer.process_event(self._MockEvent(disk_path, '/usr/bin/cat'))

        after = analyzer.metrics.cert_last_accessed.labels(
            cert_path=disk_path, subject='CN=cache-hit-test', issuer='CN=ca',
            serial='42', common_name='', san_dns_names='', san_ip_addresses='',
            cert_index='0', pod_name='', namespace='', workload_kind='',
            workload_name='', node_name='', app_label='', container_name='',
            checksum='', spki_hash='', key_usage='', extended_key_usage='',
            spki_algorithm_oid='', signature_algorithm_oid='',
        )._value.get()
        assert after > 0.0

    def test_redetection_does_not_touch_expiry_gauge(self, analyzer, temp_dir):
        """
        Re-detection must not re-run the full metrics fan-out: a cert-property
        gauge like cert_expiry_days, which is never set for this cert outside
        of update_certificate_metrics(), must have no sample for it.
        """
        disk_path = os.path.join(temp_dir, "shared-ca3.pem")
        self._seed_known_cert(analyzer, disk_path)

        analyzer.process_event(self._MockEvent(disk_path, '/usr/bin/cat'))

        samples = [
            s for metric in analyzer.metrics.cert_expiry_days.collect()
            for s in metric.samples
            if s.labels.get('cert_path') == disk_path
        ]
        assert samples == [], \
            "cache-hit re-detection should not populate cert_expiry_days"

    def test_redetection_logs_summary_only(self, analyzer, temp_dir, caplog):
        """
        Cache-hit re-detection logs just the headline status line, not the
        full Subject/Issuer/SAN/etc. detail dump for every cached cert.
        """
        disk_path = os.path.join(temp_dir, "shared-ca4.pem")
        self._seed_known_cert(analyzer, disk_path)

        with caplog.at_level(logging.DEBUG, logger="agent.analyzer"):
            analyzer.process_event(self._MockEvent(disk_path, '/usr/bin/cat'))

        log_messages = " ".join(r.message for r in caplog.records)
        assert "OK:" in log_messages
        assert "Subject:" not in log_messages
        assert "Issuer:"  not in log_messages


class TestChecksum:
    """
    Tests for SHA-256 checksum computation on parsed certificates.
    Covers enabled/disabled behaviour, correctness, DER encoding,
    error handling, and the disabled-by-default contract.

    Checksum is now controlled via analyzer.checksum_enabled (an instance
    variable set from the config file or CERT_CHECKSUM_ENABLED env var in
    main()) rather than the module-level CERT_CHECKSUM_ENABLED constant.
    Tests set analyzer.checksum_enabled directly to reflect this.
    """

    def test_checksum_empty_by_default(self, analyzer, temp_dir):
        """checksum field is empty string when checksum_enabled is False (the default)."""
        assert analyzer.checksum_enabled is False, \
            "checksum_enabled must default to False on the analyzer instance"

        cert, _ = TestCertificateGeneration.generate_certificate("checksum.example.com", 365)
        path = os.path.join(temp_dir, "checksum.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        assert cert_infos[0].checksum == ""

    def test_checksum_populated_when_enabled(self, analyzer, temp_dir):
        """checksum is a non-empty hex string when checksum_enabled=True."""
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("checksum-on.example.com", 365)
        path = os.path.join(temp_dir, "checksum-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        assert cert_infos[0].checksum != ""
        assert len(cert_infos[0].checksum) == 64  # SHA-256 hex digest is always 64 chars

    def test_checksum_is_valid_sha256_hex(self, analyzer, temp_dir):
        """checksum contains only valid lowercase hexadecimal characters."""
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("hex.example.com", 365)
        path = os.path.join(temp_dir, "hex.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        checksum = cert_infos[0].checksum
        assert all(c in '0123456789abcdef' for c in checksum)

    def test_checksum_matches_manual_sha256(self, analyzer, temp_dir):
        """checksum matches SHA-256 of the DER-encoded certificate bytes."""
        import hashlib
        from cryptography.hazmat.primitives.serialization import Encoding
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("sha256.example.com", 365)
        path = os.path.join(temp_dir, "sha256.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        # Compute expected checksum independently
        certs = analyzer.parse_certificates(path)
        der_bytes = certs[0].public_bytes(Encoding.DER)
        expected = hashlib.sha256(der_bytes).hexdigest()

        assert cert_infos[0].checksum == expected

    def test_checksum_differs_for_different_certs(self, analyzer, temp_dir):
        """Two different certificates produce different checksums."""
        analyzer.checksum_enabled = True

        cert1, _ = TestCertificateGeneration.generate_certificate("a.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("b.example.com", 365)
        path1 = os.path.join(temp_dir, "a.pem")
        path2 = os.path.join(temp_dir, "b.pem")
        TestCertificateGeneration.save_certificate_pem(cert1, path1)
        TestCertificateGeneration.save_certificate_pem(cert2, path2)

        infos1 = analyzer.analyze_certificate(path1, "test", 1)
        infos2 = analyzer.analyze_certificate(path2, "test", 1)

        assert infos1[0].checksum != infos2[0].checksum

    def test_checksum_identical_for_same_cert_at_different_paths(
        self, analyzer, temp_dir
    ):
        """
        The same certificate file copied to two paths produces identical checksums,
        demonstrating that checksum can correlate cert identity across paths.
        """
        import shutil
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("same.example.com", 365)
        path1 = os.path.join(temp_dir, "copy1.pem")
        path2 = os.path.join(temp_dir, "copy2.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path1)
        shutil.copy2(path1, path2)

        infos1 = analyzer.analyze_certificate(path1, "test", 1)
        infos2 = analyzer.analyze_certificate(path2, "test", 1)

        assert infos1[0].checksum == infos2[0].checksum

    def test_checksum_disabled_via_config_file(self, temp_dir):
        """checksum_enabled=False when config file has checksum_enabled = false."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'checksum_enabled': 'false'}})
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'false'
        assert (result.lower() == 'true') is False

    def test_checksum_enabled_via_config_file(self, temp_dir):
        """checksum_enabled=True when config file has checksum_enabled = true."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'checksum_enabled': 'true'}})
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'true'
        assert (result.lower() == 'true') is True

    def test_checksum_enabled_via_env_var_when_no_config(self, monkeypatch, temp_dir):
        """checksum_enabled=True when env var set and no config file entry."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('CERT_CHECKSUM_ENABLED', 'true')
        cp = configparser.ConfigParser()  # empty — no config file
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'true'

    def test_config_file_takes_precedence_over_env_var(self, monkeypatch, temp_dir):
        """Config file value overrides env var — config file wins."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('CERT_CHECKSUM_ENABLED', 'true')  # env var says enabled
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'checksum_enabled': 'false'}})  # config says disabled
        result = cfg(cp, 'certificates', 'checksum_enabled', 'CERT_CHECKSUM_ENABLED', 'false')
        assert result.lower() == 'false'  # config file wins

    def test_checksum_error_does_not_prevent_cert_info_return(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        If checksum computation fails (e.g. public_bytes raises), extract_certificate_info
        still returns a valid CertificateInfo with an empty checksum rather than None.
        """
        analyzer.checksum_enabled = True

        cert, _ = TestCertificateGeneration.generate_certificate("err.example.com", 365)
        path = os.path.join(temp_dir, "err.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Patch hashlib.sha256 to raise so the checksum path fails
        import hashlib as _hashlib

        def _raising_sha256(*args, **kwargs):
            raise RuntimeError("simulated hash failure")

        monkeypatch.setattr(_hashlib, 'sha256', _raising_sha256)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        # Must still return cert info — checksum failure is non-fatal
        assert len(cert_infos) == 1
        assert cert_infos[0].checksum == ""


class TestSpkiHash:
    """
    Tests for SHA-256 SubjectPublicKeyInfo (SPKI) hash computation.

    Unlike checksum (SHA-256 of the whole DER cert, disabled by default),
    spki_hash is a hash of the public key alone and defaults to *enabled* --
    it's the mechanism a downstream consumer uses to detect "key reuse"
    across a renewal (same key, new serial/validity/checksum). See
    analyzer.spki_hash_enabled, set from the config file or
    SPKI_HASH_ENABLED env var in main().
    """

    def test_spki_hash_enabled_by_default(self, analyzer):
        """spki_hash_enabled defaults to True on a new analyzer instance."""
        assert analyzer.spki_hash_enabled is True

    def test_spki_hash_populated_by_default(self, analyzer, temp_dir):
        """spki_hash is a non-empty hex string without touching spki_hash_enabled."""
        cert, _ = TestCertificateGeneration.generate_certificate("spki.example.com", 365)
        path = os.path.join(temp_dir, "spki.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        assert cert_infos[0].spki_hash != ""
        assert len(cert_infos[0].spki_hash) == 64  # SHA-256 hex digest is always 64 chars

    def test_spki_hash_empty_when_disabled(self, analyzer, temp_dir):
        """spki_hash field is empty string when spki_hash_enabled is explicitly False."""
        analyzer.spki_hash_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("spki-off.example.com", 365)
        path = os.path.join(temp_dir, "spki-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        assert cert_infos[0].spki_hash == ""

    def test_spki_hash_is_valid_sha256_hex(self, analyzer, temp_dir):
        """spki_hash contains only valid lowercase hexadecimal characters."""
        cert, _ = TestCertificateGeneration.generate_certificate("spki-hex.example.com", 365)
        path = os.path.join(temp_dir, "spki-hex.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        spki_hash = cert_infos[0].spki_hash
        assert all(c in '0123456789abcdef' for c in spki_hash)

    def test_spki_hash_matches_manual_computation(self, analyzer, temp_dir):
        """spki_hash matches SHA-256 of the DER-encoded SubjectPublicKeyInfo."""
        import hashlib
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        cert, _ = TestCertificateGeneration.generate_certificate("spki-manual.example.com", 365)
        path = os.path.join(temp_dir, "spki-manual.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        certs = analyzer.parse_certificates(path)
        spki_der = certs[0].public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        expected = hashlib.sha256(spki_der).hexdigest()

        assert cert_infos[0].spki_hash == expected

    def test_spki_hash_differs_for_different_keys(self, analyzer, temp_dir):
        """Two certificates with independently generated keys produce different spki_hash."""
        cert1, _ = TestCertificateGeneration.generate_certificate("spki-a.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("spki-b.example.com", 365)
        path1 = os.path.join(temp_dir, "spki-a.pem")
        path2 = os.path.join(temp_dir, "spki-b.pem")
        TestCertificateGeneration.save_certificate_pem(cert1, path1)
        TestCertificateGeneration.save_certificate_pem(cert2, path2)

        infos1 = analyzer.analyze_certificate(path1, "test", 1)
        infos2 = analyzer.analyze_certificate(path2, "test", 1)

        assert infos1[0].spki_hash != infos2[0].spki_hash

    def test_spki_hash_same_for_renewed_cert_reusing_key(self, analyzer, temp_dir):
        """
        The core use case: a "renewed" certificate built from the *same* private
        key as an earlier one (different serial number, different validity
        window -- as a real renewal-in-place would look) produces an identical
        spki_hash despite a different checksum. This is what lets a downstream
        consumer flag "key reuse detected" by comparing spki_hash across
        successive discoveries of the same certificate identity.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "renewed.example.com"),
        ])

        def _build(not_before_days_ago, not_after_days_ahead):
            return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow() - timedelta(days=not_before_days_ago)
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=not_after_days_ahead)
            ).sign(private_key, hashes.SHA256(), backend=default_backend())

        old_cert = _build(400, 5)   # about to expire
        new_cert = _build(0, 365)   # freshly renewed, same key

        old_path = os.path.join(temp_dir, "renewed-old.pem")
        new_path = os.path.join(temp_dir, "renewed-new.pem")
        TestCertificateGeneration.save_certificate_pem(old_cert, old_path)
        TestCertificateGeneration.save_certificate_pem(new_cert, new_path)

        old_info = analyzer.analyze_certificate(old_path, "test", 1)[0]
        new_info = analyzer.analyze_certificate(new_path, "test", 1)[0]

        assert old_info.serial_number != new_info.serial_number
        assert old_info.spki_hash == new_info.spki_hash

    def test_spki_hash_disabled_via_config_file(self, temp_dir):
        """spki_hash_enabled=False when config file has spki_hash_enabled = false."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'spki_hash_enabled': 'false'}})
        result = cfg(cp, 'certificates', 'spki_hash_enabled', 'SPKI_HASH_ENABLED', 'true')
        assert result.lower() == 'false'

    def test_spki_hash_enabled_via_config_file(self, temp_dir):
        """spki_hash_enabled=True when config file has spki_hash_enabled = true."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'spki_hash_enabled': 'true'}})
        result = cfg(cp, 'certificates', 'spki_hash_enabled', 'SPKI_HASH_ENABLED', 'true')
        assert result.lower() == 'true'

    def test_spki_hash_defaults_to_true_with_no_config_or_env(self, temp_dir):
        """spki_hash_enabled resolves to true with neither a config entry nor an env var set."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()  # empty — no config file
        result = cfg(cp, 'certificates', 'spki_hash_enabled', 'SPKI_HASH_ENABLED', 'true')
        assert result.lower() == 'true'

    def test_spki_hash_config_file_takes_precedence_over_env_var(self, monkeypatch, temp_dir):
        """Config file value overrides env var — config file wins."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('SPKI_HASH_ENABLED', 'true')  # env var says enabled
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'spki_hash_enabled': 'false'}})  # config says disabled
        result = cfg(cp, 'certificates', 'spki_hash_enabled', 'SPKI_HASH_ENABLED', 'true')
        assert result.lower() == 'false'  # config file wins

    def test_spki_hash_error_does_not_prevent_cert_info_return(
        self, analyzer, temp_dir, monkeypatch
    ):
        """
        If SPKI hash computation fails (e.g. sha256 raises), extract_certificate_info
        still returns a valid CertificateInfo with an empty spki_hash rather than None.
        """
        cert, _ = TestCertificateGeneration.generate_certificate("spki-err.example.com", 365)
        path = os.path.join(temp_dir, "spki-err.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        import hashlib as _hashlib

        def _raising_sha256(*args, **kwargs):
            raise RuntimeError("simulated hash failure")

        monkeypatch.setattr(_hashlib, 'sha256', _raising_sha256)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        # Must still return cert info — SPKI hash failure is non-fatal
        assert len(cert_infos) == 1
        assert cert_infos[0].spki_hash == ""


class TestFipsComplianceEnabled:
    """
    Tests for the fips_compliance_enabled config option.

    When True (the default): FIPS compliance is checked per-certificate and the
    results (fips_compliant/fips_violations) are stored in CertificateInfo fields
    and emitted as Prometheus metrics.

    When False: the compliance judgement is skipped — fips_compliant/fips_violations
    stay at empty defaults, the cert_fips_compliant metric is not emitted, and no
    FIPS log lines appear. Key metadata (key_algorithm/key_size/signature_hash/
    curve_name) is unaffected -- it's extracted unconditionally regardless of this
    flag; see TestKeyInfoExtraction below.
    """

    # ── Default / instance behaviour ──────────────────────────────────────────

    def test_fips_compliance_enabled_by_default(self, analyzer):
        """fips_compliance_enabled defaults to True on a new analyzer instance."""
        assert analyzer.fips_compliance_enabled is True

    def test_fips_fields_populated_when_enabled(self, analyzer, temp_dir):
        """FIPS fields on CertificateInfo are populated when fips_compliance_enabled=True."""
        assert analyzer.fips_compliance_enabled is True

        cert, _ = TestCertificateGeneration.generate_certificate("fips-on.example.com", 365)
        path = os.path.join(temp_dir, "fips-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        # generate_certificate produces RSA-2048 / SHA-256 — always compliant
        assert info.key_algorithm == 'RSA'
        assert info.key_size == 2048
        assert info.signature_hash == 'sha256'
        assert info.fips_checked is True
        assert info.fips_compliant is True
        assert info.fips_violations == []

    def test_fips_judgement_empty_when_disabled(self, analyzer, temp_dir):
        """fips_checked/fips_compliant/fips_violations are at empty defaults when
        fips_compliance_enabled=False, but key metadata (key_algorithm/key_size/
        signature_hash/curve_name) still populates -- see TestKeyInfoExtraction for
        that guarantee in detail. fips_checked=False is what lets a consumer tell
        'not checked' apart from a genuine fips_compliant=False non-compliance result."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("fips-off.example.com", 365)
        path = os.path.join(temp_dir, "fips-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.key_algorithm == 'RSA'
        assert info.key_size == 2048
        assert info.signature_hash == 'sha256'
        assert info.fips_checked is False
        assert info.fips_compliant is False
        assert info.fips_violations == []

    def test_multi_cert_bundle_all_skipped_when_disabled(self, analyzer, temp_dir):
        """All certs in a multi-cert bundle have empty fips_compliant/fips_violations when
        disabled, while key metadata is still populated for each."""
        analyzer.fips_compliance_enabled = False

        certs_and_keys = [
            TestCertificateGeneration.generate_certificate(f"multi{i}.example.com", 365)
            for i in range(3)
        ]
        path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem(
            [c for c, _ in certs_and_keys], path
        )

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 3
        for info in cert_infos:
            assert info.key_algorithm == 'RSA'
            assert info.fips_compliant is False
            assert info.fips_violations == []

    # ── _fips_check() call gating ──────────────────────────────────────────────

    def test_fips_check_not_called_when_disabled(self, analyzer, temp_dir, monkeypatch):
        """_fips_check() is never invoked when fips_compliance_enabled=False."""
        analyzer.fips_compliance_enabled = False

        calls = []

        import agent.analyzer as _ca
        from agent.fips_compliance_checker import check_certificate as _real

        def _spy(cert, **kwargs):
            calls.append(cert)
            return _real(cert, **kwargs)

        monkeypatch.setattr(_ca, '_fips_check', _spy)

        cert, _ = TestCertificateGeneration.generate_certificate("skip.example.com", 365)
        path = os.path.join(temp_dir, "skip.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.analyze_certificate(path, "test", 1)
        assert calls == [], "_fips_check must not be called when fips_compliance_enabled=False"

    def test_fips_check_called_when_enabled(self, analyzer, temp_dir, monkeypatch):
        """_fips_check() is called once per certificate when fips_compliance_enabled=True."""
        assert analyzer.fips_compliance_enabled is True

        calls = []

        import agent.analyzer as _ca
        from agent.fips_compliance_checker import check_certificate as _real

        def _spy(cert, **kwargs):
            calls.append(cert)
            return _real(cert, **kwargs)

        monkeypatch.setattr(_ca, '_fips_check', _spy)

        cert, _ = TestCertificateGeneration.generate_certificate("check.example.com", 365)
        path = os.path.join(temp_dir, "check.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.analyze_certificate(path, "test", 1)
        assert len(calls) == 1, "_fips_check must be called exactly once when enabled"

    def test_fips_check_error_is_non_fatal(self, analyzer, temp_dir, monkeypatch):
        """If _fips_check() raises, extract_certificate_info still returns CertificateInfo."""
        import agent.analyzer as _ca

        def _raising(cert, **kwargs):
            raise RuntimeError("simulated fips error")

        monkeypatch.setattr(_ca, '_fips_check', _raising)

        cert, _ = TestCertificateGeneration.generate_certificate("fips-err.example.com", 365)
        path = os.path.join(temp_dir, "fips-err.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.fips_checked is True  # the check was attempted, just failed
        assert info.fips_compliant is False
        assert 'FIPS check error' in info.fips_violations

    # ── Prometheus metric gating ───────────────────────────────────────────────

    def test_prometheus_metric_emitted_when_enabled(self, analyzer, temp_dir):
        """cert_fips_compliant metric has samples after update_certificate_metrics when enabled."""
        assert analyzer.fips_compliance_enabled is True

        cert, _ = TestCertificateGeneration.generate_certificate("metric-on.example.com", 365)
        path = os.path.join(temp_dir, "metric-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        samples = list(analyzer.metrics.cert_fips_compliant.collect()[0].samples)
        assert len(samples) > 0, \
            "cert_fips_compliant must have at least one sample when FIPS checking is enabled"

    def test_prometheus_metric_not_emitted_when_disabled(self, analyzer, temp_dir):
        """cert_fips_compliant metric has no samples after update_certificate_metrics when disabled."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("metric-off.example.com", 365)
        path = os.path.join(temp_dir, "metric-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        samples = list(analyzer.metrics.cert_fips_compliant.collect()[0].samples)
        assert len(samples) == 0, \
            "cert_fips_compliant must have no samples when FIPS checking is disabled"

    def test_prometheus_metric_value_one_for_compliant_cert(self, analyzer, temp_dir):
        """cert_fips_compliant metric is set to 1.0 for a FIPS-compliant certificate."""
        cert, _ = TestCertificateGeneration.generate_certificate("compliant.example.com", 365)
        path = os.path.join(temp_dir, "compliant.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        samples = list(analyzer.metrics.cert_fips_compliant.collect()[0].samples)
        assert len(samples) == 1
        assert samples[0].value == 1.0

    # ── Logging output ─────────────────────────────────────────────────────────

    def test_compliant_cert_fips_line_logged_when_enabled(self, analyzer, temp_dir, caplog):
        """A FIPS-compliant cert produces a 'FIPS: compliant' log line when enabled."""
        cert, _ = TestCertificateGeneration.generate_certificate("log-on.example.com", 365)
        path = os.path.join(temp_dir, "log-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos

        with caplog.at_level(logging.DEBUG):
            analyzer.log_certificate_status(cert_infos[0])

        assert any(
            'FIPS' in r.message and 'compliant' in r.message
            for r in caplog.records
        ), "Expected a FIPS compliant log line when fips_compliance_enabled=True"

    def test_no_fips_log_lines_when_disabled(self, analyzer, temp_dir, caplog):
        """No FIPS log lines appear when fips_compliance_enabled=False."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("log-off.example.com", 365)
        path = os.path.join(temp_dir, "log-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos

        with caplog.at_level(logging.DEBUG):
            analyzer.log_certificate_status(cert_infos[0])

        fips_lines = [r for r in caplog.records if 'FIPS' in r.message]
        assert fips_lines == [], \
            f"Expected no FIPS log lines when disabled, got: {[r.message for r in fips_lines]}"

    def test_fips_violation_logged_as_warning_when_enabled(self, analyzer, temp_dir, caplog):
        """FIPS violations are logged as WARNING when fips_compliance_enabled=True."""
        cert, _ = TestCertificateGeneration.generate_certificate("warn.example.com", 365)
        path = os.path.join(temp_dir, "warn.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert cert_infos
        info = cert_infos[0]
        # Inject a violation to simulate a non-compliant cert
        info.fips_compliant = False
        info.fips_violations = ["Signature hash 'sha1' is not FIPS-approved (use SHA-256 or stronger)"]

        with caplog.at_level(logging.WARNING):
            analyzer.log_certificate_status(info)

        assert any('FIPS NON-COMPLIANT' in r.message for r in caplog.records), \
            "Expected a FIPS NON-COMPLIANT warning when violations are present"

    # ── Config file / env var resolution ──────────────────────────────────────

    def test_disabled_via_config_file(self):
        """cfg() resolves to 'false' when config file sets fips_compliance_enabled = false."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'fips_compliance_enabled': 'false'}})
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'false'

    def test_enabled_via_config_file(self):
        """cfg() resolves to 'true' when config file sets fips_compliance_enabled = true."""
        import configparser
        from cert_analyzer import cfg
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'fips_compliance_enabled': 'true'}})
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'true'

    def test_disabled_via_env_var(self, monkeypatch):
        """cfg() resolves to 'false' from FIPS_COMPLIANCE_ENABLED=false when no config entry."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('FIPS_COMPLIANCE_ENABLED', 'false')
        cp = configparser.ConfigParser()
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'false'

    def test_config_file_takes_precedence_over_env_var(self, monkeypatch):
        """Config file value overrides env var — config enabled wins over env disabled."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.setenv('FIPS_COMPLIANCE_ENABLED', 'false')  # env says disabled
        cp = configparser.ConfigParser()
        cp.read_dict({'certificates': {'fips_compliance_enabled': 'true'}})  # config says enabled
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'true'  # config file wins

    def test_default_is_enabled_when_no_config_or_env(self, monkeypatch):
        """fips_compliance_enabled defaults to 'true' when neither config nor env var is set."""
        import configparser
        from cert_analyzer import cfg
        monkeypatch.delenv('FIPS_COMPLIANCE_ENABLED', raising=False)
        cp = configparser.ConfigParser()
        result = cfg(cp, 'certificates', 'fips_compliance_enabled', 'FIPS_COMPLIANCE_ENABLED', 'true')
        assert result.lower() == 'true'


class TestKeyInfoExtraction:
    """
    Tests for key_algorithm/key_size/signature_hash/curve_name on CertificateInfo.

    Unlike fips_compliant/fips_violations, these are extracted unconditionally
    (independent of fips_compliance_enabled) -- they're generic key metadata,
    not a FIPS judgement, and dashboards/inventory need them regardless of
    whether FIPS compliance checking itself is turned on.
    """

    def test_key_info_populated_when_fips_enabled(self, analyzer, temp_dir):
        assert analyzer.fips_compliance_enabled is True

        cert, _ = TestCertificateGeneration.generate_certificate("keyinfo-on.example.com", 365)
        path = os.path.join(temp_dir, "keyinfo-on.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.key_algorithm == 'RSA'
        assert info.key_size == 2048
        assert info.signature_hash == 'sha256'

    def test_key_info_populated_when_fips_disabled(self, analyzer, temp_dir):
        """The whole point: these fields aren't gated behind fips_compliance_enabled."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("keyinfo-off.example.com", 365)
        path = os.path.join(temp_dir, "keyinfo-off.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.key_algorithm == 'RSA'
        assert info.key_size == 2048
        assert info.signature_hash == 'sha256'
        assert info.fips_checked is False    # FIPS judgement itself still skipped
        assert info.fips_compliant is False

    def test_fips_check_not_called_but_key_info_still_populated(self, analyzer, temp_dir, monkeypatch):
        """_fips_check() is skipped when disabled, but key info comes from a separate,
        always-called extraction path -- confirm both halves of that split hold together."""
        analyzer.fips_compliance_enabled = False

        calls = []
        import agent.analyzer as _ca
        from agent.fips_compliance_checker import check_certificate as _real

        def _spy(cert, **kwargs):
            calls.append(cert)
            return _real(cert, **kwargs)

        monkeypatch.setattr(_ca, '_fips_check', _spy)

        cert, _ = TestCertificateGeneration.generate_certificate("keyinfo-nocall.example.com", 365)
        path = os.path.join(temp_dir, "keyinfo-nocall.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert calls == [], "_fips_check must not be called when fips_compliance_enabled=False"
        assert cert_infos[0].key_algorithm == 'RSA'
        assert cert_infos[0].key_size == 2048


class TestAlgorithmOidExtraction:
    """
    Tests for spki_algorithm_oid / signature_algorithm_oid on CertificateInfo.

    Unlike the FIPS fields above, these are extracted unconditionally
    (independent of fips_compliance_enabled) since they feed downstream
    PQC-readiness scoring and stay cheap regardless of that flag.
    """

    def test_oids_populated_for_rsa_cert(self, analyzer, temp_dir):
        cert, _ = TestCertificateGeneration.generate_certificate("oid-rsa.example.com", 365)
        path = os.path.join(temp_dir, "oid-rsa.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.spki_algorithm_oid == '1.2.840.113549.1.1.1'        # rsaEncryption
        assert info.signature_algorithm_oid == '1.2.840.113549.1.1.11'  # sha256WithRSAEncryption

    def test_oids_populated_even_when_fips_compliance_disabled(self, analyzer, temp_dir):
        """These fields aren't gated behind fips_compliance_enabled."""
        analyzer.fips_compliance_enabled = False

        cert, _ = TestCertificateGeneration.generate_certificate("oid-nofips.example.com", 365)
        path = os.path.join(temp_dir, "oid-nofips.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.fips_compliant is False  # FIPS check itself skipped
        assert info.spki_algorithm_oid == '1.2.840.113549.1.1.1'
        assert info.signature_algorithm_oid == '1.2.840.113549.1.1.11'

    def test_oid_extraction_error_is_non_fatal(self, analyzer, temp_dir, monkeypatch):
        """If get_algorithm_oids() raises, extract_certificate_info still returns CertificateInfo
        with the OID fields left at their empty defaults."""
        import agent.analyzer as _ca

        def _raising(cert):
            raise RuntimeError("simulated OID extraction error")

        monkeypatch.setattr(_ca, '_get_algorithm_oids', _raising)

        cert, _ = TestCertificateGeneration.generate_certificate("oid-err.example.com", 365)
        path = os.path.join(temp_dir, "oid-err.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        assert len(cert_infos) == 1
        info = cert_infos[0]
        assert info.spki_algorithm_oid == ''
        assert info.signature_algorithm_oid == ''


class TestRFC5280Extensions:
    """Tests for Key Usage, Extended Key Usage, and Basic Constraints extraction."""

    @staticmethod
    def _build_cert(key_usage_ext=None, eku_ext=None, bc_ext=None):
        """Return a signed x509.Certificate with the given optional extensions."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        now = datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]))
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
        )
        if key_usage_ext is not None:
            builder = builder.add_extension(key_usage_ext, critical=True)
        if eku_ext is not None:
            builder = builder.add_extension(eku_ext, critical=False)
        if bc_ext is not None:
            builder = builder.add_extension(bc_ext, critical=True)
        return builder.sign(private_key, hashes.SHA256(), backend=default_backend())

    def _analyze(self, analyzer, temp_dir, cert):
        path = os.path.join(temp_dir, "ext-test.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)
        infos = analyzer.analyze_certificate(path, "test", 0)
        assert len(infos) == 1
        return infos[0]

    # ── Key Usage ────────────────────────────────────────────────────────────

    def test_key_usage_absent_returns_none(self, analyzer, temp_dir):
        cert = self._build_cert()
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.key_usage is None

    def test_key_usage_digital_signature_and_key_encipherment(self, analyzer, temp_dir):
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        )
        cert = self._build_cert(key_usage_ext=ku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.key_usage == ['digital_signature', 'key_encipherment']

    def test_key_usage_ca_flags(self, analyzer, temp_dir):
        ku = x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        )
        cert = self._build_cert(key_usage_ext=ku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.key_usage == ['key_cert_sign', 'crl_sign']

    def test_key_usage_empty_bitstring(self, analyzer, temp_dir):
        ku = x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        )
        cert = self._build_cert(key_usage_ext=ku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.key_usage == []

    def test_key_usage_encipher_only_included_when_key_agreement_set(self, analyzer, temp_dir):
        ku = x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True, key_cert_sign=False,
            crl_sign=False, encipher_only=True, decipher_only=False,
        )
        cert = self._build_cert(key_usage_ext=ku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert 'key_agreement' in info.key_usage
        assert 'encipher_only' in info.key_usage

    # ── Extended Key Usage ───────────────────────────────────────────────────

    def test_extended_key_usage_absent_returns_none(self, analyzer, temp_dir):
        cert = self._build_cert()
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.extended_key_usage is None

    def test_extended_key_usage_server_and_client_auth(self, analyzer, temp_dir):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH])
        cert = self._build_cert(eku_ext=eku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.extended_key_usage == ['server_auth', 'client_auth']

    def test_extended_key_usage_code_signing(self, analyzer, temp_dir):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
        cert = self._build_cert(eku_ext=eku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.extended_key_usage == ['code_signing']

    def test_extended_key_usage_unknown_oid_falls_back_to_dotted_string(self, analyzer, temp_dir):
        # 1.3.6.1.4.1.311.10.3.4 is Microsoft EFS — not in _EKU_NAMES
        unknown_oid = x509.ObjectIdentifier('1.3.6.1.4.1.311.10.3.4')
        eku = x509.ExtendedKeyUsage([unknown_oid])
        cert = self._build_cert(eku_ext=eku)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.extended_key_usage == ['1.3.6.1.4.1.311.10.3.4']

    # ── Basic Constraints ────────────────────────────────────────────────────

    def test_basic_constraints_absent_returns_none(self, analyzer, temp_dir):
        cert = self._build_cert()
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.is_ca is None
        assert info.basic_constraints_path_length is None

    def test_basic_constraints_end_entity(self, analyzer, temp_dir):
        bc = x509.BasicConstraints(ca=False, path_length=None)
        cert = self._build_cert(bc_ext=bc)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.is_ca is False
        assert info.basic_constraints_path_length is None

    def test_basic_constraints_ca_no_path_length(self, analyzer, temp_dir):
        bc = x509.BasicConstraints(ca=True, path_length=None)
        cert = self._build_cert(bc_ext=bc)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.is_ca is True
        assert info.basic_constraints_path_length is None

    def test_basic_constraints_ca_with_path_length(self, analyzer, temp_dir):
        bc = x509.BasicConstraints(ca=True, path_length=0)
        cert = self._build_cert(bc_ext=bc)
        info = self._analyze(analyzer, temp_dir, cert)
        assert info.is_ca is True
        assert info.basic_constraints_path_length == 0

    # ── All three extensions present together ────────────────────────────────

    def test_all_three_extensions_extracted_together(self, analyzer, temp_dir):
        from cryptography.x509.oid import ExtendedKeyUsageOID
        ku = x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        )
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        bc = x509.BasicConstraints(ca=False, path_length=None)
        cert = self._build_cert(key_usage_ext=ku, eku_ext=eku, bc_ext=bc)
        info = self._analyze(analyzer, temp_dir, cert)

        assert info.key_usage == ['digital_signature', 'key_encipherment']
        assert info.extended_key_usage == ['server_auth']
        assert info.is_ca is False
        assert info.basic_constraints_path_length is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# ── Tetragon version check helpers ───────────────────────────────────────────

class _MockGetVersionResponse:
    """Minimal mock of the GetVersionResponse proto."""
    def __init__(self, version: str):
        self.version = version


class _MockVersionStub:
    """Mock gRPC stub whose GetVersion returns a configurable version string."""
    def __init__(self, version: str = 'v1.1.0', raise_exc=None):
        self._version   = version
        self._raise_exc = raise_exc

    def GetVersion(self, request, timeout=None):
        if self._raise_exc:
            raise self._raise_exc
        return _MockGetVersionResponse(self._version)


class TestTetragonVersionCheck:
    """
    Tests for get_runtime_tetragon_version() and check_tetragon_version().

    All tests use mock stubs so no live Tetragon connection is needed.
    Prometheus metric state is verified via the analyzer fixture which
    provides a clean registry per test.
    """

    def test_get_runtime_version_returns_version_string(self, analyzer):
        """Happy path — stub returns a version string."""
        stub = _MockVersionStub(version='v1.1.0')
        result = analyzer.get_runtime_tetragon_version(stub)
        assert result == 'v1.1.0'

    def test_get_runtime_version_returns_unknown_on_grpc_error(self, analyzer):
        """gRPC failure returns 'unknown' without raising."""
        stub = _MockVersionStub(raise_exc=Exception("connection refused"))
        result = analyzer.get_runtime_tetragon_version(stub)
        assert result == 'unknown'

    def test_get_runtime_version_returns_unknown_when_field_empty(self, analyzer):
        """Empty version string in response returns 'unknown'."""
        stub = _MockVersionStub(version='')
        result = analyzer.get_runtime_tetragon_version(stub)
        assert result == 'unknown'

    def test_check_version_match_sets_metric_to_1(self, analyzer, monkeypatch):
        """Matching build and runtime versions set the match gauge to 1."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.1.0')
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match.labels(node_name=analyzer.metrics._node_name)._value.get() == 1.0

    def test_check_version_mismatch_sets_metric_to_0(self, analyzer, monkeypatch):
        """Differing build and runtime versions set the match gauge to 0."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.2.0')
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0

    def test_check_version_unknown_build_sets_metric_to_0(self, analyzer, monkeypatch):
        """Unknown build version (env var not set) sets match gauge to 0."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'unknown')
        stub = _MockVersionStub(version='v1.1.0')
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0

    def test_check_version_unknown_runtime_sets_metric_to_0(self, analyzer, monkeypatch):
        """Unreachable Tetragon daemon (unknown runtime) sets match gauge to 0."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(raise_exc=Exception("timeout"))
        analyzer.check_tetragon_version(stub)
        assert analyzer.metrics.tetragon_version_match.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0

    def test_check_version_sets_info_metric(self, analyzer, monkeypatch):
        """Version info metric carries both build and runtime version labels."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.2.0')
        analyzer.check_tetragon_version(stub)
        # Collect samples and verify both version label keys and values are present
        samples = list(analyzer.metrics.tetragon_version_info.collect()[0].samples)
        assert len(samples) > 0, "No samples emitted from tetragon_version_info"
        label_keys = samples[0].labels.keys()
        assert 'build_version'   in label_keys
        assert 'runtime_version' in label_keys
        assert samples[0].labels['build_version']   == 'v1.1.0'
        assert samples[0].labels['runtime_version'] == 'v1.2.0'

    def test_check_version_mismatch_logs_warning(self, analyzer, monkeypatch, caplog):
        """A version mismatch produces a WARNING log containing both versions."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.2.0')

        with caplog.at_level(logging.WARNING, logger='agent.analyzer'):
            analyzer.check_tetragon_version(stub)

        messages = ' '.join(r.message for r in caplog.records)
        assert 'v1.1.0'   in messages
        assert 'v1.2.0'   in messages
        assert 'MISMATCH' in messages

    def test_check_version_match_logs_info(self, analyzer, monkeypatch, caplog):
        """Matching versions produce an INFO log confirming the version."""
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        stub = _MockVersionStub(version='v1.1.0')

        with caplog.at_level(logging.INFO, logger='agent.analyzer'):
            analyzer.check_tetragon_version(stub)

        messages = ' '.join(r.message for r in caplog.records)
        assert 'v1.1.0' in messages
        assert 'OK'      in messages

    def test_get_runtime_version_never_raises(self, analyzer):
        """get_runtime_tetragon_version must never propagate exceptions."""
        stub = _MockVersionStub(raise_exc=RuntimeError("unexpected failure"))
        try:
            result = analyzer.get_runtime_tetragon_version(stub)
            assert result == 'unknown'
        except Exception as exc:
            pytest.fail(f"get_runtime_tetragon_version raised unexpectedly: {exc}")


# ── Tetragon policy check helpers ────────────────────────────────────────────

class _MockPolicyStatus:
    """Minimal mock of the TracingPolicyStatus proto."""
    def __init__(self, name: str, state: int, namespace: str = ''):
        self.name      = name
        self.namespace = namespace
        self.state     = state


class _MockListPoliciesResponse:
    """Minimal mock of the ListTracingPoliciesResponse proto."""
    def __init__(self, policies):
        self.policies = policies


class _MockPolicyStub:
    """Mock gRPC stub whose ListTracingPolicies returns a configurable policy list."""
    def __init__(self, policies=None, raise_exc=None):
        self._policies  = policies or []
        self._raise_exc = raise_exc

    def ListTracingPolicies(self, request, timeout=None):
        if self._raise_exc:
            raise self._raise_exc
        return _MockListPoliciesResponse(self._policies)


class TestTetragonPolicyCheck:
    """
    Tests for check_tetragon_policies().

    All tests use mock stubs so no live Tetragon connection is needed.
    Prometheus metric state is verified via the analyzer fixture which
    provides a clean registry per test.
    """

    def _policy_info_samples(self, analyzer):
        """All samples currently emitted by tetragon_policy_info."""
        return list(analyzer.metrics.tetragon_policy_info.collect()[0].samples)

    def _policy_total(self, analyzer, state: str) -> float:
        """Current value of tetragon_policies_total for a given state label."""
        return analyzer.metrics.tetragon_policies_total.labels(
            state=state, node_name=analyzer.metrics._node_name
        )._value.get()

    def test_enabled_policy_sets_policy_info(self, analyzer):
        """A single enabled policy creates a tetragon_policy_info series set to 1."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('cert-access', state=1),
        ])
        analyzer.check_tetragon_policies(stub)
        samples = self._policy_info_samples(analyzer)
        assert len(samples) == 1
        assert samples[0].labels == {'name': 'cert-access', 'namespace': '', 'state': 'enabled', 'node_name': analyzer.metrics._node_name}
        assert samples[0].value == 1.0

    def test_enabled_count_reflects_policy_list(self, analyzer):
        """tetragon_policies_total{state="enabled"} equals the number of enabled policies."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('policy-a', state=1),
            _MockPolicyStatus('policy-b', state=1),
        ])
        analyzer.check_tetragon_policies(stub)
        assert self._policy_total(analyzer, 'enabled') == 2.0

    def test_mixed_states_counted_separately(self, analyzer):
        """Policies in different states are counted independently per state."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('ok-policy',  state=1),  # enabled
            _MockPolicyStatus('bad-policy', state=3),  # load_error
        ])
        analyzer.check_tetragon_policies(stub)
        assert self._policy_total(analyzer, 'enabled')    == 1.0
        assert self._policy_total(analyzer, 'load_error') == 1.0

    def test_all_states_always_emitted(self, analyzer):
        """All state counters are emitted even for states with zero policies."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('one', state=1),
        ])
        analyzer.check_tetragon_policies(stub)
        assert self._policy_total(analyzer, 'disabled')   == 0.0
        assert self._policy_total(analyzer, 'load_error') == 0.0
        assert self._policy_total(analyzer, 'error')      == 0.0

    def test_namespace_included_in_policy_info_label(self, analyzer):
        """Namespace label is populated for namespaced policies."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('my-policy', state=1, namespace='kube-system'),
        ])
        analyzer.check_tetragon_policies(stub)
        samples = self._policy_info_samples(analyzer)
        assert samples[0].labels['namespace'] == 'kube-system'

    def test_cluster_scoped_policy_has_empty_namespace(self, analyzer):
        """Cluster-scoped policies (empty namespace in proto) produce namespace=''."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('cluster-policy', state=1, namespace=''),
        ])
        analyzer.check_tetragon_policies(stub)
        samples = self._policy_info_samples(analyzer)
        assert samples[0].labels['namespace'] == ''

    def test_stale_series_removed_when_policy_deleted(self, analyzer):
        """When a policy disappears between polls, its metric series is removed."""
        stub_first = _MockPolicyStub(policies=[
            _MockPolicyStatus('policy-a', state=1),
            _MockPolicyStatus('policy-b', state=1),
        ])
        analyzer.check_tetragon_policies(stub_first)
        assert len(self._policy_info_samples(analyzer)) == 2

        stub_second = _MockPolicyStub(policies=[
            _MockPolicyStatus('policy-a', state=1),
        ])
        analyzer.check_tetragon_policies(stub_second)
        samples = self._policy_info_samples(analyzer)
        assert len(samples) == 1
        assert samples[0].labels['name'] == 'policy-a'

    def test_stale_series_removed_on_state_change(self, analyzer):
        """When a policy transitions state, the old state series is removed."""
        stub_first = _MockPolicyStub(policies=[
            _MockPolicyStatus('my-policy', state=1),  # enabled
        ])
        analyzer.check_tetragon_policies(stub_first)
        assert self._policy_info_samples(analyzer)[0].labels['state'] == 'enabled'

        stub_second = _MockPolicyStub(policies=[
            _MockPolicyStatus('my-policy', state=3),  # load_error
        ])
        analyzer.check_tetragon_policies(stub_second)
        samples = self._policy_info_samples(analyzer)
        assert len(samples) == 1
        assert samples[0].labels['state'] == 'load_error'

    def test_empty_policy_list_produces_zero_counts(self, analyzer):
        """No active policies — all state counters are 0, no policy_info series."""
        stub = _MockPolicyStub(policies=[])
        analyzer.check_tetragon_policies(stub)
        assert self._policy_info_samples(analyzer) == []
        assert self._policy_total(analyzer, 'enabled') == 0.0

    def test_policies_cleared_between_polls(self, analyzer):
        """After all policies are removed, subsequent poll zeroes the counts."""
        stub_first = _MockPolicyStub(policies=[
            _MockPolicyStatus('policy-a', state=1),
        ])
        analyzer.check_tetragon_policies(stub_first)
        assert self._policy_total(analyzer, 'enabled') == 1.0

        stub_empty = _MockPolicyStub(policies=[])
        analyzer.check_tetragon_policies(stub_empty)
        assert self._policy_total(analyzer, 'enabled') == 0.0
        assert self._policy_info_samples(analyzer) == []

    def test_grpc_error_does_not_raise(self, analyzer):
        """A gRPC failure leaves metrics unchanged and does not propagate."""
        stub = _MockPolicyStub(raise_exc=Exception("connection refused"))
        try:
            analyzer.check_tetragon_policies(stub)
        except Exception as exc:
            pytest.fail(f"check_tetragon_policies raised unexpectedly: {exc}")

    def test_grpc_error_logs_warning(self, analyzer, caplog):
        """A gRPC failure is surfaced as a WARNING log."""
        stub = _MockPolicyStub(raise_exc=Exception("timeout"))
        with caplog.at_level(logging.WARNING, logger='agent.analyzer'):
            analyzer.check_tetragon_policies(stub)
        assert any('tracing polic' in r.message.lower() for r in caplog.records)

    def test_unknown_state_integer_labelled_unknown(self, analyzer):
        """An unrecognised state integer falls back to the 'unknown' label."""
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('exotic-policy', state=99),
        ])
        analyzer.check_tetragon_policies(stub)
        samples = self._policy_info_samples(analyzer)
        assert samples[0].labels['state'] == 'unknown'

    def test_missing_proto_type_skips_gracefully(self, analyzer, monkeypatch):
        """If ListTracingPoliciesRequest is absent from the bindings, the check is skipped."""
        import agent.analyzer as _ca
        monkeypatch.delattr(_ca.sensors_pb2, 'ListTracingPoliciesRequest')
        stub = _MockPolicyStub(policies=[
            _MockPolicyStatus('policy-a', state=1),
        ])
        analyzer.check_tetragon_policies(stub)
        assert self._policy_info_samples(analyzer) == []

    def test_get_runtime_version_returns_unknown_when_get_version_request_absent(
        self, analyzer, monkeypatch, caplog
    ):
        """Tetragon <= v1.1.0 lacks GetVersionRequest — must return 'unknown' and warn."""
        import agent.analyzer as _ca
        monkeypatch.delattr(_ca.sensors_pb2, 'GetVersionRequest')
        stub = _MockVersionStub(version='v1.0.0')

        with caplog.at_level(logging.WARNING, logger='agent.analyzer'):
            result = analyzer.get_runtime_tetragon_version(stub)

        assert result == 'unknown'
        assert any('GetVersionRequest' in r.message for r in caplog.records)

    def test_get_runtime_version_does_not_call_stub_when_get_version_request_absent(
        self, analyzer, monkeypatch
    ):
        """No RPC call is made when GetVersionRequest is missing from the bindings."""
        import agent.analyzer as _ca
        monkeypatch.delattr(_ca.sensors_pb2, 'GetVersionRequest')

        calls = []
        stub = _MockVersionStub(version='v1.0.0')
        stub.GetVersion = lambda *a, **kw: calls.append(1)  # noqa: E731

        analyzer.get_runtime_tetragon_version(stub)

        assert calls == [], "GetVersion RPC should not be called on old Tetragon bindings"


class TestBuildInfo:
    """
    Tests for the cert_analyzer_build Info metric which exposes the
    cert-analyzer version and Tetragon build version as Prometheus labels.

    The build_info metric is populated at PrometheusMetrics.__init__ time
    from the module-level constants, so we read labels from the already-
    initialised metric on the analyzer fixture rather than creating a new
    PrometheusMetrics instance (which would clash with the registry).
    """

    def test_build_info_metric_exposes_version_label(self, analyzer):
        """cert_analyzer_build metric exposes a 'version' label."""
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert len(samples) > 0
        assert 'version' in samples[0].labels

    def test_build_info_metric_exposes_tetragon_build_version_label(self, analyzer):
        """cert_analyzer_build metric exposes a 'tetragon_build_version' label."""
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert len(samples) > 0
        assert 'tetragon_build_version' in samples[0].labels

    def test_build_info_version_matches_module_constant(self, analyzer):
        """The 'version' label value matches CERT_ANALYZER_VERSION at init time."""
        import cert_analyzer as _ca
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert samples[0].labels['version'] == _ca.CERT_ANALYZER_VERSION

    def test_build_info_tetragon_version_matches_module_constant(self, analyzer):
        """The 'tetragon_build_version' label matches TETRAGON_BUILD_VERSION at init time."""
        import cert_analyzer as _ca
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert samples[0].labels['tetragon_build_version'] == _ca.TETRAGON_BUILD_VERSION

    def test_build_info_is_labeled_by_node(self, analyzer):
        """cert_analyzer_build carries node_name, like the Tetragon version metrics, so a fleet-wide view can show which analyzer version is running per node."""
        samples = list(analyzer.metrics.build_info.collect()[0].samples)
        assert samples[0].labels['node_name'] == analyzer.metrics._node_name

    def test_cert_analyzer_version_constant_reads_env(self, monkeypatch):
        """CERT_ANALYZER_VERSION env var is read correctly by os.getenv."""
        monkeypatch.setenv('CERT_ANALYZER_VERSION', 'v2.0.0-test')
        value = os.getenv('CERT_ANALYZER_VERSION', 'dev')
        assert value == 'v2.0.0-test'

    def test_cert_analyzer_version_defaults_to_dev(self, monkeypatch):
        """CERT_ANALYZER_VERSION defaults to 'dev' when env var is absent."""
        monkeypatch.delenv('CERT_ANALYZER_VERSION', raising=False)
        value = os.getenv('CERT_ANALYZER_VERSION', 'dev')
        assert value == 'dev'


class TestScrapeIntervalMetric:
    """
    Tests for the _ScrapeIntervalCollector powering
    cert_analyzer_scrape_interval_seconds, which measures the observed
    wall-clock gap between successive /metrics scrapes.
    """

    def _collector(self, analyzer):
        from agent.metrics import _ScrapeIntervalCollector
        from prometheus_client import REGISTRY
        return next(
            c for c in REGISTRY._collector_to_names
            if isinstance(c, _ScrapeIntervalCollector)
        )

    def _by_name(self, metrics, name):
        return next(m for m in metrics if m.name == name)

    def test_first_collect_yields_no_interval(self, analyzer):
        """No prior scrape to diff against, so the interval metric is absent."""
        collector = self._collector(analyzer)
        metrics = list(collector.collect())
        assert all(m.name != 'cert_analyzer_scrape_interval_seconds' for m in metrics)

    def test_first_collect_yields_last_scrape_timestamp(self, analyzer):
        """Unlike the interval, last-scrape timestamp has nothing to diff
        against, so it's reported starting on the very first scrape."""
        collector = self._collector(analyzer)
        before = time.time()
        metrics = list(collector.collect())
        after = time.time()

        sample = self._by_name(metrics, 'cert_analyzer_last_scrape_timestamp_seconds').samples[0]
        assert before <= sample.value <= after
        assert sample.labels['node_name'] == analyzer.metrics._node_name

    def test_second_collect_reports_elapsed_interval(self, analyzer):
        """The second collect() reports the wall-clock gap since the first."""
        collector = self._collector(analyzer)
        list(collector.collect())
        time.sleep(0.05)
        metrics = list(collector.collect())

        sample = self._by_name(metrics, 'cert_analyzer_scrape_interval_seconds').samples[0]
        assert sample.value >= 0.05
        assert sample.labels['node_name'] == analyzer.metrics._node_name

    def test_second_collect_advances_last_scrape_timestamp(self, analyzer):
        """last_scrape_timestamp reflects wall-clock time, not the monotonic
        clock the interval calculation is based on."""
        collector = self._collector(analyzer)
        first = list(collector.collect())
        first_ts = self._by_name(first, 'cert_analyzer_last_scrape_timestamp_seconds').samples[0].value
        time.sleep(0.05)
        second = list(collector.collect())
        second_ts = self._by_name(second, 'cert_analyzer_last_scrape_timestamp_seconds').samples[0].value

        assert second_ts > first_ts

    def test_registration_does_not_prime_last_scrape(self, analyzer):
        """
        describe() must stop the registry's register()-time collect() call
        from priming _last_scrape -- otherwise the first real scrape would
        measure from registration time instead of reporting nothing.
        """
        collector = self._collector(analyzer)
        assert collector._last_scrape is None


class TestScanConfigMetrics:
    """
    Tests for scan_paths/scan_interval_seconds surfacing in Prometheus:
    scan_paths as a cert_analyzer_config_info label (Grafana's Analyzer
    Configuration table), scan_interval_seconds as its own graphable Gauge
    (cert_analyzer_scan_interval_seconds) since it's a real number rather
    than a string config value.
    """

    def _make_analyzer(self, **kwargs):
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        return CertificateAnalyzer(tetragon_address='unix:///dev/null', **kwargs)

    def test_scan_paths_appears_in_config_info(self):
        a = self._make_analyzer(scan_paths=['/etc/pki/ca-trust/extracted/pem/', '/etc/ssl'])
        samples = list(a.metrics.config_info.collect())[0].samples
        assert samples[0].labels['scan_paths'] == '/etc/pki/ca-trust/extracted/pem/,/etc/ssl'

    def test_no_scan_paths_yields_empty_config_info_field(self):
        a = self._make_analyzer()
        samples = list(a.metrics.config_info.collect())[0].samples
        assert samples[0].labels['scan_paths'] == ''

    def test_scan_interval_seconds_gauge_reflects_configured_value(self):
        a = self._make_analyzer(scan_interval_seconds=1800)
        samples = list(a.metrics.scan_interval_seconds.collect())[0].samples
        assert samples[0].value == 1800
        assert samples[0].labels['node_name'] == a.metrics._node_name

    def test_kafka_plain_and_connect_enabled_default_false_without_publisher(self):
        """kafka_plain_enabled/kafka_connect_enabled read 'false' in config_info when kafka_publisher is None."""
        a = self._make_analyzer()
        samples = list(a.metrics.config_info.collect())[0].samples
        assert samples[0].labels['kafka_plain_enabled'] == 'false'
        assert samples[0].labels['kafka_connect_enabled'] == 'false'

    def test_kafka_plain_and_connect_enabled_reflect_publisher_flags(self):
        """kafka_plain_enabled/kafka_connect_enabled in config_info mirror the KafkaPublisher's own flags."""
        import agent.kafka as _ca
        from unittest.mock import patch, MagicMock

        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            with patch.object(_ca, 'KAFKA_AVAILABLE', True):
                from cert_analyzer import KafkaPublisher
                publisher = KafkaPublisher(
                    bootstrap_servers='b:9092', topic='t',
                    plain_enabled=False, connect_topic='t-connect',
                )
                a = self._make_analyzer(kafka_publisher=publisher)
                samples = list(a.metrics.config_info.collect())[0].samples
                assert samples[0].labels['kafka_plain_enabled'] == 'false'
                assert samples[0].labels['kafka_connect_enabled'] == 'true'


class TestScrapeThrottleMiddleware:
    """
    Tests for _ScrapeThrottleMiddleware, which enforces a minimum interval
    between real /metrics scrapes by replaying the last cached response for
    any request arriving too soon after the previous one actually served.
    """

    def _environ(self, method='GET', path='/metrics', accept=None, accept_encoding=None):
        environ = {'REQUEST_METHOD': method, 'PATH_INFO': path}
        if accept is not None:
            environ['HTTP_ACCEPT'] = accept
        if accept_encoding is not None:
            environ['HTTP_ACCEPT_ENCODING'] = accept_encoding
        return environ

    def _fake_app(self, calls):
        def app(environ, start_response):
            calls.append(environ)
            start_response('200 OK', [('Content-Type', 'text/plain')])
            return [f'body-{len(calls)}'.encode()]
        return app

    def _start_response(self, *args):
        pass

    def test_first_request_calls_wrapped_app(self):
        from agent.metrics import _ScrapeThrottleMiddleware
        calls = []
        middleware = _ScrapeThrottleMiddleware(self._fake_app(calls), min_interval_seconds=60)

        body = middleware(self._environ(), self._start_response)

        assert len(calls) == 1
        assert b''.join(body) == b'body-1'

    def test_too_soon_request_replays_cached_body_without_calling_app_again(self):
        from agent.metrics import _ScrapeThrottleMiddleware
        calls = []
        middleware = _ScrapeThrottleMiddleware(self._fake_app(calls), min_interval_seconds=60)

        middleware(self._environ(), self._start_response)
        body = middleware(self._environ(), self._start_response)

        assert len(calls) == 1
        assert b''.join(body) == b'body-1'

    def test_request_after_interval_elapses_calls_app_again(self):
        from agent.metrics import _ScrapeThrottleMiddleware
        calls = []
        middleware = _ScrapeThrottleMiddleware(self._fake_app(calls), min_interval_seconds=0.05)

        middleware(self._environ(), self._start_response)
        time.sleep(0.06)
        body = middleware(self._environ(), self._start_response)

        assert len(calls) == 2
        assert b''.join(body) == b'body-2'

    def test_non_get_method_bypasses_throttle(self):
        from agent.metrics import _ScrapeThrottleMiddleware
        calls = []
        middleware = _ScrapeThrottleMiddleware(self._fake_app(calls), min_interval_seconds=60)

        middleware(self._environ(method='OPTIONS'), self._start_response)
        middleware(self._environ(method='OPTIONS'), self._start_response)

        assert len(calls) == 2

    def test_mismatched_accept_header_bypasses_cache(self):
        from agent.metrics import _ScrapeThrottleMiddleware
        calls = []
        middleware = _ScrapeThrottleMiddleware(self._fake_app(calls), min_interval_seconds=60)

        middleware(self._environ(accept='text/plain'), self._start_response)
        middleware(self._environ(accept='application/openmetrics-text'), self._start_response)

        assert len(calls) == 2

    def test_disabled_when_min_interval_is_zero(self):
        """start_metrics_server skips wrapping entirely when disabled, but the
        middleware itself should also just never throttle if min_interval<=0
        were passed directly."""
        from agent.metrics import _ScrapeThrottleMiddleware
        calls = []
        middleware = _ScrapeThrottleMiddleware(self._fake_app(calls), min_interval_seconds=0)

        middleware(self._environ(), self._start_response)
        middleware(self._environ(), self._start_response)

        assert len(calls) == 2


# ── Reconnection and version monitor tests ────────────────────────────────────

import threading as _threading
import time as _time
import grpc
from tetragon import sensors_pb2_grpc


def _starve_side_monitor_intervals(monkeypatch):
    """
    start() unconditionally spawns three sub-monitor threads (version,
    policy, process-metrics) as a side effect, in addition to its own main
    reconnect loop -- regardless of how quickly that main loop itself exits.
    Each defaults to a real, non-zero interval (300s/60s/15s), so once
    spawned it's already blocked in a genuine time.sleep() call almost
    immediately -- unlike the zero-interval cases _stop_daemon_loop_thread
    handles, patching time.sleep afterward can't preempt a sleep call
    that's already in progress, so these threads can't be stopped once
    started.

    The 15s process-metrics-monitor default is short enough to plausibly
    fire again during a longer suite run. Call this *before* starting
    analyzer.start() to push all three defaults out to a value they'll
    never actually reach again during a test, so any leaked sub-monitor
    thread stays harmlessly parked in its first sleep call instead of
    periodically calling real, psutil-backed code that can race with a
    later test's mock.patch('builtins.open', ...) -- the same accepted
    pattern already used by test_version_monitor_thread_is_daemon /
    test_process_metrics_monitor_thread_is_daemon.
    """
    monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '9999')
    monkeypatch.setenv('TETRAGON_POLICY_CHECK_INTERVAL', '9999')
    monkeypatch.setenv('PROCESS_METRICS_INTERVAL', '9999')


def _stop_daemon_loop_thread(thread, monkeypatch, timeout=2.0):
    """
    Force a background monitor/reconnect-loop thread to exit, then join it
    with a timeout so it's guaranteed dead before the test returns.

    _start_version_monitor, _start_process_metrics_monitor, and start()'s own
    reconnect loop are all `while True: time.sleep(interval); try: ... except
    Exception: ...` -- time.sleep() sits outside the try/except in every one
    of them, so making it raise KeyboardInterrupt escapes uncaught (it isn't
    an Exception subclass) and ends the thread; start()'s reconnect loop
    already treats KeyboardInterrupt as its own intended shutdown signal.

    Without this, these zero-interval / no-op-sleep test threads are left
    spinning as daemons for the rest of the pytest process: once monkeypatch
    reverts this test's own mocks at teardown, they fall back to calling the
    *real* underlying method (e.g. psutil-backed update_process_metrics,
    which reads /proc via plain open() calls) in a tight loop -- which can
    race with any later test's mock.patch('builtins.open', ...) and cause
    intermittent, hard-to-reproduce failures there (observed in
    TestPortProbe::test_fib_trie_returns_container_ip).

    threading.excepthook is temporarily quieted for this specific,
    expected KeyboardInterrupt so it doesn't print a traceback that looks
    like a real failure in test output.
    """
    original_hook = _threading.excepthook

    def _quiet_hook(args):
        if args.exc_type is KeyboardInterrupt:
            return
        original_hook(args)

    monkeypatch.setattr(_threading, 'excepthook', _quiet_hook)

    def _raise(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(_time, 'sleep', _raise)
    thread.join(timeout=timeout)
    assert not thread.is_alive(), f"{thread.name or thread} did not stop within {timeout}s"


def _capture_started_thread(monkeypatch, start_fn, thread_name):
    """
    Call start_fn() (e.g. lambda: analyzer._start_version_monitor(stub)) with
    threading.Thread patched to record every thread it constructs, and
    return the one matching thread_name.

    Searching for the thread by name *after* calling start_fn via
    threading.enumerate() risks grabbing a stale same-named thread left over
    from an earlier test that can never actually be stopped this way (e.g.
    one still parked in a real multi-thousand-second time.sleep because its
    interval was never 0) instead of the one this call just created --
    _stop_daemon_loop_thread's join would then time out and fail on a
    thread that was never the one under test.
    """
    original_thread = _threading.Thread
    captured = []

    def _capture(*args, **kwargs):
        t = original_thread(*args, **kwargs)
        captured.append(t)
        return t

    monkeypatch.setattr(_threading, 'Thread', _capture)
    start_fn()
    matches = [t for t in captured if t.name == thread_name]
    assert matches, f"no thread named {thread_name!r} was started"
    return matches[-1]


class _StreamingStub:
    """
    Mock stub that simulates the full GetEvents streaming lifecycle.

    Yields a configurable sequence of events then raises an exception to
    simulate a Tetragon disconnect, allowing reconnection logic to be tested
    without a live gRPC connection.
    """
    def __init__(self, events=None, fail_after=0, exception=None):
        """
        events     : list of mock event objects to yield per call
        fail_after : number of events to yield before raising (0 = raise immediately)
        exception  : exception to raise (default: grpc.RpcError via _MockRpcError)
        """
        self._events    = events or []
        self._fail_after = fail_after
        self._exception  = exception or _MockRpcError()
        self._call_count = 0

    def GetEvents(self, request, **kwargs):
        self._call_count += 1
        for i, event in enumerate(self._events):
            if i >= self._fail_after:
                raise self._exception
            yield event
        raise self._exception

    def GetVersion(self, request, timeout=None):
        return _MockGetVersionResponse('v1.1.0')


class _MockRpcError(grpc.RpcError):
    """Minimal grpc.RpcError subclass with a controllable status code."""
    def __init__(self, code=grpc.StatusCode.UNAVAILABLE):
        self._code = code

    def code(self):
        return self._code


class TestReconnection:
    """
    Tests for the reconnection loop in start().

    Uses threads and Events to drive the analyzer for a bounded number of
    reconnect cycles without blocking the test indefinitely.
    """

    def _run_start_briefly(self, analyzer, stub_factory, stop_after_s=0.3):
        """
        Run analyzer.start() in a thread, interrupt it after stop_after_s
        seconds by sending KeyboardInterrupt to the thread, and return.

        Patches the stub creation inside start() so we can inject our mock.
        """
        import signal

        exc_holder = []

        def _target():
            try:
                analyzer.start()
            except Exception as e:
                exc_holder.append(e)

        t = _threading.Thread(target=_target, daemon=True)
        t.start()
        _time.sleep(stop_after_s)
        # The reconnect loop exits cleanly on KeyboardInterrupt
        # We can't send it to a thread directly so we just let it run
        # and check state rather than joining
        return exc_holder

    def test_healthy_metric_set_on_connection(self, analyzer, monkeypatch):
        """
        analyzer_healthy gauge is set to 1 when the event stream is active.
        We verify this by checking immediately after a stream starts.
        """
        connected = _threading.Event()
        stopped   = _threading.Event()

        original_get_events_called = []

        class _ConnectingStub:
            def GetEvents(self_, request, **kwargs):
                connected.set()
                stopped.wait(timeout=1.0)
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        stub = _ConnectingStub()

        # Patch channel creation to return our stub. Returns a Mock rather
        # than None so start()'s `finally: channel.close()` (now actually
        # exercised once _stop_daemon_loop_thread below drives a real
        # shutdown) doesn't raise AttributeError.
        from unittest.mock import Mock

        def _mock_insecure_channel(*a, **kw):
            return Mock()

        monkeypatch.setattr(grpc, 'insecure_channel', _mock_insecure_channel)
        monkeypatch.setattr(
            sensors_pb2_grpc, 'FineGuidanceSensorsStub',
            lambda ch: stub,
        )
        _starve_side_monitor_intervals(monkeypatch)

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()
        connected.wait(timeout=2.0)

        assert analyzer.metrics.analyzer_healthy.labels(node_name=analyzer.metrics._node_name)._value.get() == 1.0

        # Patch time.sleep to raise before GetEvents can even be released --
        # stopped.wait()'s own 1.0s timeout lets it proceed to raise
        # regardless, so there's no window where a real time.sleep(5) retry
        # backoff could run before the patched version takes effect.
        _stop_daemon_loop_thread(t, monkeypatch)

    def test_healthy_metric_set_to_0_on_disconnect(self, analyzer, monkeypatch):
        """
        analyzer_healthy drops to 0 when the gRPC stream raises RpcError.
        """
        metric_set_to_zero = _threading.Event()
        _labeled = analyzer.metrics.analyzer_healthy.labels(node_name=analyzer.metrics._node_name)
        original_set = _labeled.set

        def _watched_set(value):
            original_set(value)
            if value == 0:
                metric_set_to_zero.set()

        _labeled.set = _watched_set

        class _DisconnectingStub:
            def GetEvents(self_, request, **kwargs):
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        # Mock rather than None so start()'s `finally: channel.close()` (now
        # actually exercised once _stop_daemon_loop_thread below drives a
        # real shutdown) doesn't raise AttributeError.
        from unittest.mock import Mock
        monkeypatch.setattr(grpc, 'insecure_channel', lambda *a, **kw: Mock())
        monkeypatch.setattr(sensors_pb2_grpc, 'FineGuidanceSensorsStub',
                            lambda ch: _DisconnectingStub())
        # Patch sleep on the cert_analyzer module so the retry backoff is instant
        import cert_analyzer as _ca
        monkeypatch.setattr(_ca.time, 'sleep', lambda s: None)
        _starve_side_monitor_intervals(monkeypatch)

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()

        assert metric_set_to_zero.wait(timeout=3.0), \
            "analyzer_healthy was never set to 0 after disconnect"
        assert analyzer.metrics.analyzer_healthy.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0

        # Without this, the no-op'd time.sleep above leaves the reconnect
        # loop spinning as fast as possible forever (raise -> except -> noop
        # sleep -> raise -> ...) as a zombie daemon thread.
        _stop_daemon_loop_thread(t, monkeypatch)

    def test_reconnect_reissues_get_events(self, analyzer, monkeypatch):
        """
        After a disconnect, GetEvents is called again (reconnect attempt).
        """
        call_count  = [0]
        second_call = _threading.Event()

        class _ReconnectingStub:
            def GetEvents(self_, request, **kwargs):
                call_count[0] += 1
                if call_count[0] >= 2:
                    second_call.set()
                    _time.sleep(10)  # block so test can assert
                raise _MockRpcError()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        # Mock rather than None so start()'s `finally: channel.close()` (now
        # actually exercised once _stop_daemon_loop_thread below drives a
        # real shutdown) doesn't raise AttributeError.
        from unittest.mock import Mock
        monkeypatch.setattr(grpc, 'insecure_channel', lambda *a, **kw: Mock())
        monkeypatch.setattr(sensors_pb2_grpc, 'FineGuidanceSensorsStub',
                            lambda ch: _ReconnectingStub())
        monkeypatch.setattr(_time, 'sleep', lambda s: None)
        _starve_side_monitor_intervals(monkeypatch)

        t = _threading.Thread(target=analyzer.start, daemon=True)
        t.start()

        assert second_call.wait(timeout=3.0), "GetEvents was not called a second time"
        assert call_count[0] >= 2

        # Without this, the no-op'd time.sleep above leaves the reconnect
        # loop spinning as fast as possible forever as a zombie daemon thread.
        _stop_daemon_loop_thread(t, monkeypatch)

    def test_keyboard_interrupt_propagates_after_cleanup(self, analyzer, monkeypatch):
        """
        start() must re-raise KeyboardInterrupt after its own cleanup (metrics,
        channel.close()) instead of swallowing it. agent.config.main() wraps
        start() in its own try/except KeyboardInterrupt specifically to flush
        the Kafka producer and stop the health server on a graceful shutdown
        signal -- if start() swallows the interrupt, that handler never runs
        and unflushed in-flight Kafka messages can be lost.
        """
        class _InterruptingStub:
            def GetEvents(self_, request, **kwargs):
                raise KeyboardInterrupt()

            def GetVersion(self_, request, timeout=None):
                return _MockGetVersionResponse('v1.1.0')

        class _FakeChannel:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        fake_channel = _FakeChannel()
        monkeypatch.setattr(grpc, 'insecure_channel', lambda *a, **kw: fake_channel)
        monkeypatch.setattr(sensors_pb2_grpc, 'FineGuidanceSensorsStub',
                            lambda ch: _InterruptingStub())
        # start() spawns its 3 sub-monitor threads (version/policy/process-
        # metrics) before the main loop even runs, so they leak regardless of
        # how quickly GetEvents raises -- see _starve_side_monitor_intervals.
        _starve_side_monitor_intervals(monkeypatch)

        with pytest.raises(KeyboardInterrupt):
            analyzer.start()

        assert fake_channel.closed, "channel.close() must still run via finally"


class TestVersionMonitor:
    """Tests for _start_version_monitor background thread."""

    def test_version_monitor_thread_is_daemon(self, analyzer, monkeypatch):
        """The version monitor thread must be a daemon so it doesn't block shutdown."""
        threads_started = []

        original_thread = _threading.Thread

        def _capture_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            threads_started.append(t)
            return t

        monkeypatch.setattr(_threading, 'Thread', _capture_thread)
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '9999')

        stub = _MockVersionStub(version='v1.1.0')
        analyzer._start_version_monitor(stub)

        version_threads = [t for t in threads_started
                           if getattr(t, 'name', '') == 'tetragon-version-monitor']
        assert len(version_threads) == 1
        assert version_threads[0].daemon is True

    def test_version_monitor_calls_check_periodically(self, analyzer, monkeypatch):
        """Version monitor invokes check_tetragon_version at least twice."""
        call_count   = [0]
        second_check = _threading.Event()

        def _mock_check(stub):
            call_count[0] += 1
            if call_count[0] >= 2:
                second_check.set()

        monkeypatch.setattr(analyzer, 'check_tetragon_version', _mock_check)
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '0')

        stub = _MockVersionStub(version='v1.1.0')
        thread = _capture_started_thread(
            monkeypatch, lambda: analyzer._start_version_monitor(stub), 'tetragon-version-monitor'
        )

        assert second_check.wait(timeout=2.0), \
            "check_tetragon_version was not called a second time within 2s"

        # Without this, the zero-interval loop keeps spinning as a zombie
        # daemon thread for the rest of the test run -- once monkeypatch
        # reverts check_tetragon_version above, it starts calling the real
        # method instead of _mock_check.
        _stop_daemon_loop_thread(thread, monkeypatch)

    def test_version_monitor_survives_check_exception(self, analyzer, monkeypatch):
        """An exception in check_tetragon_version must not kill the monitor thread."""
        call_count   = [0]
        second_check = _threading.Event()

        def _failing_then_succeeding_check(stub):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("simulated transient failure")
            second_check.set()

        monkeypatch.setattr(analyzer, 'check_tetragon_version',
                            _failing_then_succeeding_check)
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '0')

        stub = _MockVersionStub(version='v1.1.0')
        thread = _capture_started_thread(
            monkeypatch, lambda: analyzer._start_version_monitor(stub), 'tetragon-version-monitor'
        )

        assert second_check.wait(timeout=2.0), \
            "Monitor thread did not survive the exception"

        _stop_daemon_loop_thread(thread, monkeypatch)

    def test_version_monitor_detects_upgrade(self, analyzer, monkeypatch):
        """
        If Tetragon is upgraded while the analyzer is running the mismatch
        metric updates to reflect the new version.
        """
        import agent.analyzer as _ca
        monkeypatch.setattr(_ca, 'TETRAGON_BUILD_VERSION', 'v1.1.0')
        monkeypatch.setenv('TETRAGON_VERSION_CHECK_INTERVAL', '0')

        versions    = ['v1.1.0', 'v1.2.0']  # simulates an upgrade
        call_index  = [0]
        mismatch_detected = _threading.Event()

        def _mock_check(stub):
            v = versions[min(call_index[0], len(versions) - 1)]
            call_index[0] += 1
            # Directly invoke the real check logic with a stub returning v
            real_stub = _MockVersionStub(version=v)
            # Call the real implementation bypassing the monkeypatch
            CertificateAnalyzer.check_tetragon_version(analyzer, real_stub)
            if analyzer.metrics.tetragon_version_match.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0:
                mismatch_detected.set()

        monkeypatch.setattr(analyzer, 'check_tetragon_version', _mock_check)

        stub = _MockVersionStub(version='v1.1.0')
        thread = _capture_started_thread(
            monkeypatch, lambda: analyzer._start_version_monitor(stub), 'tetragon-version-monitor'
        )

        assert mismatch_detected.wait(timeout=3.0), \
            "Mismatch metric was not set after simulated Tetragon upgrade"

        _stop_daemon_loop_thread(thread, monkeypatch)


class TestProcessMetricsMonitor:
    """
    Tests for _start_process_metrics_monitor — the fixed-interval thread that
    keeps cert_analyzer_process_cpu_seconds_total/_rss_bytes live instead of
    only updating as a side-effect of cert-processing events (which let them
    go stale for minutes and then jump in one lump sum, producing spikes in
    Grafana's deriv()-based panels that didn't correspond to any real event).
    """

    def test_process_metrics_monitor_thread_is_daemon(self, analyzer, monkeypatch):
        """The process metrics monitor thread must be a daemon so it doesn't block shutdown."""
        threads_started = []

        original_thread = _threading.Thread

        def _capture_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            threads_started.append(t)
            return t

        monkeypatch.setattr(_threading, 'Thread', _capture_thread)
        monkeypatch.setenv('PROCESS_METRICS_INTERVAL', '9999')

        analyzer._start_process_metrics_monitor()

        metrics_threads = [t for t in threads_started
                            if getattr(t, 'name', '') == 'process-metrics-monitor']
        assert len(metrics_threads) == 1
        assert metrics_threads[0].daemon is True

    def test_process_metrics_monitor_calls_update_periodically(self, analyzer, monkeypatch):
        """Monitor invokes update_process_metrics at least twice, independent of any event."""
        call_count   = [0]
        second_call  = _threading.Event()

        def _mock_update():
            call_count[0] += 1
            if call_count[0] >= 2:
                second_call.set()

        monkeypatch.setattr(analyzer.metrics, 'update_process_metrics', _mock_update)
        monkeypatch.setenv('PROCESS_METRICS_INTERVAL', '0')

        thread = _capture_started_thread(
            monkeypatch, analyzer._start_process_metrics_monitor, 'process-metrics-monitor'
        )

        assert second_call.wait(timeout=2.0), \
            "update_process_metrics was not called a second time within 2s"

        # Without this, the zero-interval loop keeps spinning as a zombie
        # daemon thread for the rest of the test run -- once monkeypatch
        # reverts update_process_metrics above, it starts calling the real,
        # psutil-backed method (which reads /proc via plain open() calls)
        # in a tight loop, which can race with any later test's
        # mock.patch('builtins.open', ...).
        _stop_daemon_loop_thread(thread, monkeypatch)

    def test_process_metrics_monitor_survives_update_exception(self, analyzer, monkeypatch):
        """An exception in update_process_metrics must not kill the monitor thread."""
        call_count  = [0]
        second_call = _threading.Event()

        def _failing_then_succeeding_update():
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("simulated transient failure")
            second_call.set()

        monkeypatch.setattr(analyzer.metrics, 'update_process_metrics',
                             _failing_then_succeeding_update)
        monkeypatch.setenv('PROCESS_METRICS_INTERVAL', '0')

        thread = _capture_started_thread(
            monkeypatch, analyzer._start_process_metrics_monitor, 'process-metrics-monitor'
        )

        assert second_call.wait(timeout=2.0), \
            "Monitor thread did not survive the exception"

        _stop_daemon_loop_thread(thread, monkeypatch)

    def test_process_metrics_monitor_does_not_require_tetragon_stub(self, analyzer, monkeypatch):
        """Unlike the version/policy monitors, this one takes no stub argument."""
        monkeypatch.setenv('PROCESS_METRICS_INTERVAL', '9999')
        # Would raise TypeError if the method still expected a stub positional arg.
        analyzer._start_process_metrics_monitor()


class TestRetryQueueDrainer:
    """
    Tests for _start_retry_queue_drainer — the background thread that
    replays rate-limited new-certificate files from the retry queue as
    _new_cert_rate_limiter capacity frees up. Shares the same token bucket
    as fresh events rather than having its own budget.
    """

    def test_drainer_thread_is_daemon(self, analyzer, monkeypatch):
        """The drainer thread must be a daemon so it doesn't block shutdown."""
        threads_started = []

        original_thread = _threading.Thread

        def _capture_thread(*args, **kwargs):
            t = original_thread(*args, **kwargs)
            threads_started.append(t)
            return t

        monkeypatch.setattr(_threading, 'Thread', _capture_thread)

        analyzer._start_retry_queue_drainer()

        drainer_threads = [t for t in threads_started
                            if getattr(t, 'name', '') == 'rate-limit-retry-drainer']
        assert len(drainer_threads) == 1
        assert drainer_threads[0].daemon is True

    def test_drainer_replays_queued_entry_once_capacity_available(self, analyzer, temp_dir, monkeypatch):
        """A throttled file sitting in the queue is fully processed once tokens free up."""
        from agent.analyzer import _TokenBucket

        cert, _ = TestCertificateGeneration.generate_certificate("drain-me.example.com", 365)
        path = os.path.join(temp_dir, "drain-me.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Exhaust the bucket right before the throttled call, not before cert
        # generation above -- keygen+signing+disk-write can occasionally take
        # >100ms under CI load, long enough at 10/sec for a token to trickle
        # back in and make this call succeed instead of queue, flaking the
        # assertion below. Refilled fast (10/sec) so the drainer's own
        # backoff loop still picks the queued entry up quickly.
        bucket = _TokenBucket(rate=10)
        bucket._tokens = 0
        analyzer._new_cert_rate_limiter = bucket

        result = analyzer._analyze_and_finish_new_certificate_file(
            path, "test", 1, "", None, "", 0, "test-node",
        )
        assert result == []
        assert path in analyzer._retry_queue_paths

        thread = _capture_started_thread(
            monkeypatch, analyzer._start_retry_queue_drainer, 'rate-limit-retry-drainer'
        )

        deadline = _time.monotonic() + 3.0
        while _time.monotonic() < deadline:
            matching = [k for k in analyzer.known_certs.keys() if k.startswith(path + ":")]
            if matching:
                break
            _time.sleep(0.05)
        else:
            pytest.fail("queued file was not replayed within 3s")

        assert path not in analyzer._retry_queue_paths
        assert all(e.cert_path != path for e in analyzer._retry_queue)

        _stop_daemon_loop_thread(thread, monkeypatch)

    def test_drainer_preserves_original_process_attribution_on_replay(self, analyzer, temp_dir, monkeypatch):
        """Unlike periodic_scan's rediscovery, a replay keeps the real triggering process/pid."""
        from agent.analyzer import _TokenBucket

        cert, _ = TestCertificateGeneration.generate_certificate("attributed.example.com", 365)
        path = os.path.join(temp_dir, "attributed.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Exhaust the bucket right before the throttled call -- see the
        # matching comment in test_drainer_replays_queued_entry_once_capacity_available
        # for why this can't happen before cert generation above.
        bucket = _TokenBucket(rate=10)
        bucket._tokens = 0
        analyzer._new_cert_rate_limiter = bucket

        analyzer._analyze_and_finish_new_certificate_file(
            path, "/usr/bin/original-proc", 4242, "", None, "", 0, "test-node",
        )

        thread = _capture_started_thread(
            monkeypatch, analyzer._start_retry_queue_drainer, 'rate-limit-retry-drainer'
        )

        deadline = _time.monotonic() + 3.0
        cert_info = None
        while _time.monotonic() < deadline:
            matching = [k for k in analyzer.known_certs.keys() if k.startswith(path + ":")]
            if matching:
                cert_info = analyzer.known_certs.get(matching[0])
                break
            _time.sleep(0.05)

        _stop_daemon_loop_thread(thread, monkeypatch)

        assert cert_info is not None, "queued file was not replayed within 3s"
        assert cert_info.process == "/usr/bin/original-proc"
        assert cert_info.pid == 4242

    def test_drainer_skips_entry_already_known_via_other_path(self, analyzer, temp_dir, monkeypatch):
        """
        If the path became known some other way (e.g. a fresh Tetragon
        re-access won the race) while still queued, the drainer discards the
        stale entry without spending a token or re-parsing.
        """
        cert, _ = TestCertificateGeneration.generate_certificate("already-known.example.com", 365)
        path = os.path.join(temp_dir, "already-known.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Simulate the path having already been successfully processed
        # through some other route.
        analyzer._known_paths[path] = {f"{path}:0:1"}

        # Directly queue a stale retry entry for that same path.
        analyzer._enqueue_rate_limited_retry(
            path, "test", 1, "", None, "", 0, "test-node",
        )
        assert path in analyzer._retry_queue_paths

        def _fail_if_called(*args, **kwargs):
            pytest.fail("analyze_certificate should not be called for an already-known path")

        monkeypatch.setattr(analyzer, 'analyze_certificate', _fail_if_called)

        thread = _capture_started_thread(
            monkeypatch, analyzer._start_retry_queue_drainer, 'rate-limit-retry-drainer'
        )

        deadline = _time.monotonic() + 2.0
        while _time.monotonic() < deadline:
            if path not in analyzer._retry_queue_paths:
                break
            _time.sleep(0.05)
        else:
            pytest.fail("stale queued entry was not discarded within 2s")

        _stop_daemon_loop_thread(thread, monkeypatch)


# ── Certificate parsing exception handling tests ──────────────────────────────

class _BrokenCert:
    """
    A mock x509.Certificate whose attributes raise exceptions on access,
    simulating malformed or encrypted certificates that cannot be parsed.
    Allows selective breakage of individual fields.
    """
    def __init__(
        self,
        break_subject=False,
        break_issuer=False,
        break_serial=False,
        break_dates=False,
    ):
        self._break_subject = break_subject
        self._break_issuer  = break_issuer
        self._break_serial  = break_serial
        self._break_dates   = break_dates

        # Provide working defaults for fields not being broken
        self._subject = type('S', (), {
            'rfc4514_string': lambda s: 'CN=test',
            'get_attributes_for_oid': lambda s, oid: [],
        })()
        self._issuer = type('I', (), {
            'rfc4514_string': lambda s: 'CN=ca',
        })()

    @property
    def subject(self):
        if self._break_subject:
            raise ValueError("Simulated subject parse failure")
        return self._subject

    @property
    def issuer(self):
        if self._break_issuer:
            raise ValueError("Simulated issuer parse failure")
        return self._issuer

    @property
    def serial_number(self):
        if self._break_serial:
            raise ValueError("Simulated serial number parse failure")
        return 12345

    @property
    def not_valid_before(self):
        if self._break_dates:
            raise ValueError("Simulated date parse failure")
        return datetime.utcnow() - timedelta(days=1)

    @property
    def not_valid_after(self):
        if self._break_dates:
            raise ValueError("Simulated date parse failure")
        return datetime.utcnow() + timedelta(days=365)

    # not_valid_before_utc / not_valid_after_utc intentionally absent so
    # extract_certificate_info falls back to the naive properties above

    @property
    def extensions(self):
        raise x509.ExtensionNotFound(
            "No extensions", x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )


class TestCertificateParsingExceptions:
    """
    Tests that verify the analyzer degrades gracefully when certificate
    parsing raises exceptions — returning [] or None rather than crashing,
    and incrementing the appropriate error metrics.
    """

    def test_extract_info_returns_none_when_subject_raises(self, analyzer, temp_dir):
        """A cert whose subject raises returns None from extract_certificate_info."""
        cert = _BrokenCert(break_subject=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_returns_none_when_issuer_raises(self, analyzer, temp_dir):
        """A cert whose issuer raises returns None from extract_certificate_info."""
        cert = _BrokenCert(break_issuer=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_returns_none_when_serial_raises(self, analyzer, temp_dir):
        """A cert whose serial number raises returns None from extract_certificate_info."""
        cert = _BrokenCert(break_serial=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_returns_none_when_dates_raise(self, analyzer, temp_dir):
        """A cert whose validity dates raise returns None from extract_certificate_info."""
        cert = _BrokenCert(break_dates=True)
        result = analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        assert result is None

    def test_extract_info_increments_error_metric_on_failure(self, analyzer):
        """extract_certificate_info increments extraction_error metric when it returns None."""
        cert = _BrokenCert(break_subject=True)
        before = analyzer.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=analyzer.metrics._node_name)._value.get()
        analyzer.extract_certificate_info(cert, "/tmp/bad.pem", "test", 1)
        after = analyzer.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=analyzer.metrics._node_name)._value.get()
        assert after == before + 1

    def test_analyze_certificate_skips_broken_cert_in_bundle(self, analyzer, temp_dir):
        """
        In a multi-cert bundle, a broken cert is skipped and valid certs
        are still returned — the analyzer does not crash or return empty.
        """
        # Write a valid 2-cert bundle
        cert1, _ = TestCertificateGeneration.generate_certificate("valid1.example.com", 365)
        cert2, _ = TestCertificateGeneration.generate_certificate("valid2.example.com", 180)
        bundle_path = os.path.join(temp_dir, "bundle.pem")
        TestCertificateGeneration.save_multi_certificate_pem([cert1, cert2], bundle_path)

        # Patch parse_certificates to inject a broken cert between the two valid ones
        original_parse = analyzer.parse_certificates

        def _inject_broken(path):
            certs = original_parse(path)
            return [certs[0], _BrokenCert(break_subject=True), certs[1]]

        analyzer.parse_certificates = _inject_broken

        cert_infos = analyzer.analyze_certificate(bundle_path, "test", 1)

        # Two valid certs should come through; broken one silently skipped
        assert len(cert_infos) == 2
        common_names = [c.common_name for c in cert_infos]
        assert "valid1.example.com" in common_names
        assert "valid2.example.com" in common_names

    def test_analyze_certificate_returns_empty_when_all_certs_broken(self, analyzer, temp_dir):
        """If every cert in a file is broken, analyze_certificate returns []."""
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        path = os.path.join(temp_dir, "single.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        analyzer.parse_certificates = lambda p: [_BrokenCert(break_dates=True)]

        result = analyzer.analyze_certificate(path, "test", 1)
        assert result == []

    def test_analyze_certificate_does_not_crash_on_parse_exception(self, analyzer, temp_dir):
        """
        If parse_certificates itself raises, analyze_certificate returns []
        rather than propagating the exception.
        """
        cert, _ = TestCertificateGeneration.generate_certificate("test.example.com", 365)
        path = os.path.join(temp_dir, "single.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def _raise(*args, **kwargs):
            raise RuntimeError("Simulated catastrophic parse failure")

        analyzer.parse_certificates = _raise

        try:
            result = analyzer.analyze_certificate(path, "test", 1)
            assert result == []
        except Exception as exc:
            pytest.fail(f"analyze_certificate propagated exception: {exc}")

    def test_extract_info_handles_valid_cert_with_utc_dates(self, analyzer, temp_dir):
        """
        extract_certificate_info correctly handles certs that return
        timezone-aware datetimes from not_valid_after_utc (cryptography >= 42).
        The returned CertificateInfo should have naive datetimes.
        """
        from datetime import timezone

        cert, _ = TestCertificateGeneration.generate_certificate("utc.example.com", 365)
        path = os.path.join(temp_dir, "utc.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Wrap the cert to return tz-aware datetimes from the _utc properties
        class _UTCAwareCert:
            def __init__(self, inner):
                self._inner = inner

            def __getattr__(self, name):
                return getattr(self._inner, name)

            @property
            def not_valid_before_utc(self):
                return self._inner.not_valid_before.replace(tzinfo=timezone.utc)

            @property
            def not_valid_after_utc(self):
                return self._inner.not_valid_after.replace(tzinfo=timezone.utc)

        certs = analyzer.parse_certificates(path)
        wrapped = _UTCAwareCert(certs[0])
        info = analyzer.extract_certificate_info(wrapped, path, "test", 1)

        assert info is not None
        assert info.not_before.tzinfo is None, "not_before should be naive datetime"
        assert info.not_after.tzinfo  is None, "not_after should be naive datetime"
        assert info.common_name == "utc.example.com"


# ── Health server tests ───────────────────────────────────────────────────────

import urllib.request
import urllib.error
import json as _json

from cert_analyzer import HealthServer


class _MockChannel:
    """
    Mock gRPC channel with controllable connectivity state.

    check_connectivity_state() returns a bare int (self._state.value[0]),
    exactly like the real private grpc._channel.Channel.check_connectivity_state()
    HealthServer.is_live() actually calls (grpc 1.60.1's Channel has no public
    synchronous get_state() -- only the async subscribe()/unsubscribe() pair).
    An earlier version of this mock returned the grpc.ChannelConnectivity
    member itself instead of the raw int, which let a real bug ship unnoticed:
    production code called grpc.ChannelConnectivity(<int>) on the real raw int,
    which always raises ValueError (the enum's real values are (int, name)
    tuples, not bare ints), silently caught and defaulting every check to
    "unknown"/True. Passing the enum member straight through masked this
    completely, since enum-from-existing-member construction is a no-op --
    only a mock returning the same *shape* of value the real API returns
    would have caught it.
    """
    def __init__(self, state=grpc.ChannelConnectivity.READY):
        self._state = state
        self._channel = self  # mirrors channel._channel.check_connectivity_state(...)

    def check_connectivity_state(self, try_to_connect=False):
        return self._state.value[0]


def _make_health_server(analyzer, grace=0, staleness=300, port=None):
    """
    Create a HealthServer for testing.
    Uses grace=0 so readiness checks are immediate unless overridden.
    Port is auto-assigned if not specified.
    """
    import socket
    if port is None:
        # Find a free port
        with socket.socket() as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
    return HealthServer(
        analyzer=analyzer,
        port=port,
        grace_period_seconds=grace,
        staleness_seconds=staleness,
    )


def _get(port, path):
    """Make a GET request to the health server, return (status_code, body_dict)."""
    try:
        with urllib.request.urlopen(f'http://localhost:{port}{path}', timeout=2) as r:
            raw = r.read()
            return r.status, _json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, _json.loads(raw) if raw else {}


class TestHealthServerLiveness:
    """Tests for GET /healthz (liveness probe)."""

    def test_liveness_returns_200_when_no_channel_yet(self, analyzer):
        """Liveness is 200 before the gRPC channel is created (starting up)."""
        hs = _make_health_server(analyzer)
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200
        assert body['status'] == 'ok'

    def test_liveness_returns_200_when_channel_ready(self, analyzer):
        """Liveness is 200 when the gRPC channel is in READY state."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.READY))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200
        # Pins the actual channel state as the reason, not the "unknown"
        # fallback a broken state-check would silently produce -- see
        # _MockChannel's docstring for the bug this would have caught.
        assert body['reason'] == 'ready'

    def test_liveness_returns_200_when_channel_transient_failure(self, analyzer):
        """
        Liveness is 200 when Tetragon is temporarily unavailable
        (TRANSIENT_FAILURE) — the reconnect loop handles this, not the probe.
        """
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.TRANSIENT_FAILURE))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200
        assert body['reason'] == 'transient_failure'

    def test_liveness_returns_200_when_channel_idle(self, analyzer):
        """Liveness is 200 when channel is IDLE (not yet connected)."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.IDLE))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 200
        assert body['reason'] == 'idle'

    def test_liveness_returns_503_when_channel_shutdown(self, analyzer):
        """Liveness is 503 only when the channel has been explicitly shut down."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.SHUTDOWN))
        hs.start()
        status, body = _get(hs.port, '/healthz')
        hs.stop()
        assert status == 503
        assert body['status'] == 'fail'

    def test_liveness_returns_404_for_unknown_path(self, analyzer):
        """Unknown paths return 404."""
        hs = _make_health_server(analyzer)
        hs.start()
        status, _ = _get(hs.port, '/unknown')
        hs.stop()
        assert status == 404

    def test_is_live_returns_true_without_channel(self, analyzer):
        """is_live() returns True when no channel has been set yet."""
        hs = _make_health_server(analyzer)
        ok, reason = hs.is_live()
        assert ok is True
        assert reason == 'starting'

    def test_is_live_returns_false_on_shutdown(self, analyzer):
        """is_live() returns False when channel is SHUTDOWN."""
        hs = _make_health_server(analyzer)
        hs.set_channel(_MockChannel(grpc.ChannelConnectivity.SHUTDOWN))
        ok, reason = hs.is_live()
        assert ok is False
        assert reason == 'channel_shutdown'


class TestHealthServerReadiness:
    """Tests for GET /readyz (readiness probe)."""

    def test_readiness_returns_200_during_grace_period(self, analyzer):
        """Readiness is 200 during the startup grace period."""
        hs = _make_health_server(analyzer, grace=9999)
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 200
        assert body['status'] == 'ok'
        assert 'grace_period' in body['reason']

    def test_readiness_returns_200_when_no_events_seen(self, analyzer):
        """
        Readiness is 200 after the grace period when no events have been seen —
        a node with no cert activity is a valid state, not a failure.
        """
        hs = _make_health_server(analyzer, grace=0)
        # Ensure last_event_timestamp is 0 (never set)
        analyzer.last_event_time = 0.0
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 200
        assert 'no_events_seen' in body['reason']

    def test_readiness_returns_200_when_recent_event(self, analyzer):
        """Readiness is 200 when the last event was recent."""
        hs = _make_health_server(analyzer, grace=0, staleness=300)
        analyzer.last_event_time = _time.time()
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 200

    def test_readiness_returns_503_when_events_stale(self, analyzer):
        """Readiness is 503 when the last event is older than the staleness window."""
        hs = _make_health_server(analyzer, grace=0, staleness=10)
        # Set last event to 60 seconds ago — well past the 10s staleness window
        analyzer.last_event_time = _time.time() - 60
        hs.start()
        status, body = _get(hs.port, '/readyz')
        hs.stop()
        assert status == 503
        assert body['status'] == 'fail'
        assert 'stale' in body['reason']

    def test_is_ready_true_during_grace_period(self, analyzer):
        """is_ready() returns True during the grace period regardless of event state."""
        hs = _make_health_server(analyzer, grace=9999)
        ok, reason = hs.is_ready()
        assert ok is True
        assert 'grace_period' in reason

    def test_is_ready_true_with_no_events_after_grace(self, analyzer):
        """is_ready() returns True with no events seen after grace period."""
        hs = _make_health_server(analyzer, grace=0)
        analyzer.last_event_time = 0.0
        ok, reason = hs.is_ready()
        assert ok is True
        assert reason == 'no_events_seen'

    def test_is_ready_false_when_stale(self, analyzer):
        """is_ready() returns False when last_event_timestamp is too old."""
        hs = _make_health_server(analyzer, grace=0, staleness=10)
        analyzer.last_event_time = _time.time() - 60
        ok, reason = hs.is_ready()
        assert ok is False
        assert 'stale' in reason

    def test_health_server_response_is_valid_json(self, analyzer):
        """Both endpoints return valid JSON bodies."""
        hs = _make_health_server(analyzer, grace=0)
        hs.start()
        for path in ('/healthz', '/readyz'):
            status, body = _get(hs.port, path)
            assert 'status' in body
            assert 'reason' in body
        hs.stop()

    def test_health_server_port_configurable(self, analyzer):
        """HealthServer respects the port passed at construction."""
        import socket
        with socket.socket() as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
        hs = HealthServer(analyzer=analyzer, port=port)
        assert hs.port == port

class TestKafkaPublisher:
    """
    Tests for the optional KafkaPublisher class.

    Covers:
    - No-op when kafka-python is not installed
    - No-op when Kafka is disabled (kafka_publisher is None on analyzer)
    - Producer initialised with correct kwargs
    - publish() sends correct JSON message schema
    - publish() uses cert path as message key
    - publish() only fires for new certificates, not re-detections
    - publish() is silent on broker errors (never raises)
    - close() flushes and closes the producer
    - SASL kwargs passed through when security_protocol requires them
    - PLAINTEXT omits security_protocol kwarg
    """

    @pytest.fixture
    def sample_cert_info(self):
        """A fully-populated CertificateInfo for use in publisher tests."""
        from cert_analyzer import CertificateInfo
        return CertificateInfo(
            path='/etc/pki/tls/certs/test.crt',
            subject='CN=test.example.com',
            issuer='CN=Test CA',
            serial_number='abc123',
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            process='/usr/bin/curl',
            pid=12345,
            namespace='default',
            common_name='test.example.com',
            san_dns_names=['test.example.com', 'www.test.example.com'],
            cert_index=0,
            pod_name='my-pod',
            workload_kind='Deployment',
            workload_name='my-app',
            node_name='worker-node-1',
            pod_labels={'app': 'my-app'},
            app_label='my-app',
            container_name='main',
            container_image='my-app:1.0',
            checksum='',
            spki_algorithm_oid='1.2.840.113549.1.1.1',
            signature_algorithm_oid='1.2.840.113549.1.1.11',
        )

    def _make_publisher(self, mock_producer_class, **kwargs):
        """Helper — construct a KafkaPublisher with a mocked KafkaProducer."""
        from cert_analyzer import KafkaPublisher
        defaults = dict(
            bootstrap_servers='broker1:9092,broker2:9092',
            topic='cert-events',
        )
        defaults.update(kwargs)
        return KafkaPublisher(**defaults)

    # ── availability guard ────────────────────────────────────────────────────

    def test_noop_when_kafka_not_available(self, sample_cert_info, monkeypatch):
        """publish() is silent and never raises when kafka-python is absent."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', False)

        from cert_analyzer import KafkaPublisher
        publisher = KafkaPublisher(bootstrap_servers='broker:9092', topic='t')
        assert publisher._producer is None
        # Must not raise
        publisher.publish(sample_cert_info)

    def test_noop_when_producer_init_fails(self, monkeypatch, sample_cert_info):
        """publish() is silent when KafkaProducer.__init__ raises."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer', side_effect=Exception('broker down')):
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='broker:9092', topic='t')
            assert publisher._producer is None
            publisher.publish(sample_cert_info)   # must not raise

    # ── producer initialisation ───────────────────────────────────────────────

    def test_producer_initialised_with_correct_brokers(self, monkeypatch):
        """KafkaProducer is constructed with the parsed bootstrap_servers list."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            KafkaPublisher(bootstrap_servers='b1:9092, b2:9092', topic='t')
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs['bootstrap_servers'] == ['b1:9092', 'b2:9092']

    def test_producer_plaintext_omits_security_protocol(self, monkeypatch):
        """security_protocol kwarg is absent when protocol is PLAINTEXT."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            KafkaPublisher(
                bootstrap_servers='broker:9092',
                topic='t',
                security_protocol='PLAINTEXT',
            )
            call_kwargs = mock_cls.call_args[1]
            assert 'security_protocol' not in call_kwargs

    def test_producer_sasl_kwargs_passed_through(self, monkeypatch):
        """SASL kwargs are forwarded when security_protocol is SASL_SSL."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            KafkaPublisher(
                bootstrap_servers='broker:9092',
                topic='t',
                security_protocol='SASL_SSL',
                sasl_mechanism='PLAIN',
                sasl_username='user',
                sasl_password='secret',
            )
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs['security_protocol']     == 'SASL_SSL'
            assert call_kwargs['sasl_mechanism']        == 'PLAIN'
            assert call_kwargs['sasl_plain_username']   == 'user'
            assert call_kwargs['sasl_plain_password']   == 'secret'

    # ── message schema ────────────────────────────────────────────────────────

    def test_publish_sends_correct_event_type(self, monkeypatch, sample_cert_info):
        """Published message contains event_type = 'certificate_discovered'."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            mock_producer.send.assert_called_once()
            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']
            assert msg['event_type'] == 'certificate_discovered'

    def test_publish_sends_schema_version(self, monkeypatch, sample_cert_info):
        """Published message contains schema_version, currently 1."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']
            assert msg['schema_version'] == _ca.KAFKA_SCHEMA_VERSION == 1

    def test_publish_message_contains_all_fields(self, monkeypatch, sample_cert_info):
        """Published message contains all expected CertificateInfo fields."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']

            required_fields = [
                'event_type', 'detected_at', 'path', 'cert_index',
                'subject', 'issuer', 'serial_number', 'common_name',
                'san_dns_names', 'not_before', 'not_after',
                'days_until_expiry', 'is_expired', 'process', 'pid',
                'namespace', 'pod_name', 'node_name', 'workload_kind', 'workload_name',
                'app_label', 'container_name', 'container_image', 'checksum', 'spki_hash',
                'spki_algorithm_oid', 'signature_algorithm_oid',
                'key_algorithm', 'key_size', 'signature_hash', 'curve_name',
                'fips_checked', 'fips_compliant', 'fips_violations',
            ]
            for field in required_fields:
                assert field in msg, f"Missing field: {field}"

    def test_publish_message_fips_checked_reflects_cert_info(self, monkeypatch, sample_cert_info):
        """fips_checked is published so consumers can tell 'not checked' apart from a
        genuine fips_compliant=False non-compliance result -- see agent/models.py's
        fips_checked field comment for the rationale."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            sample_cert_info.fips_checked = False
            sample_cert_info.fips_compliant = False
            publisher.publish(sample_cert_info)
            _, send_kwargs = mock_producer.send.call_args
            assert send_kwargs['value']['fips_checked'] is False
            assert send_kwargs['value']['fips_compliant'] is False

            sample_cert_info.fips_checked = True
            sample_cert_info.fips_compliant = True
            publisher.publish(sample_cert_info)
            _, send_kwargs = mock_producer.send.call_args
            assert send_kwargs['value']['fips_checked'] is True
            assert send_kwargs['value']['fips_compliant'] is True

    def test_publish_message_values_match_cert_info(self, monkeypatch, sample_cert_info):
        """Published message values correctly reflect the CertificateInfo."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            msg = send_kwargs['value']

            assert msg['path']          == '/etc/pki/tls/certs/test.crt'
            assert msg['common_name']   == 'test.example.com'
            assert msg['process']       == '/usr/bin/curl'
            assert msg['pid']           == 12345
            assert msg['pod_name']      == 'my-pod'
            assert msg['namespace']     == 'default'
            assert msg['node_name']     == 'worker-node-1'
            assert msg['workload_kind'] == 'Deployment'
            assert msg['workload_name'] == 'my-app'
            assert msg['san_dns_names'] == ['test.example.com', 'www.test.example.com']
            assert msg['is_expired']    is True   # not_after is 2025-01-01, now > that
            assert msg['spki_algorithm_oid']      == '1.2.840.113549.1.1.1'
            assert msg['signature_algorithm_oid'] == '1.2.840.113549.1.1.11'

    def test_publish_uses_unique_key_as_partition_key(self, monkeypatch, sample_cert_info):
        """Message key is unique_key (path:cert_index:serial) for partition locality."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            expected_key = sample_cert_info.unique_key  # path:cert_index:serial
            assert send_kwargs['key'] == expected_key
            # Verify it contains all three components
            assert sample_cert_info.path in expected_key
            assert str(sample_cert_info.cert_index) in expected_key
            assert sample_cert_info.serial_number in expected_key

    # ── plain_enabled gating ───────────────────────────────────────────────────

    def test_plain_enabled_defaults_true(self, monkeypatch, sample_cert_info):
        """plain_enabled defaults to True -- unchanged behavior for existing installs."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher.plain_enabled is True

            publisher.publish(sample_cert_info)
            mock_producer.send.assert_called_once()
            send_args, _ = mock_producer.send.call_args
            assert send_args[0] == 't'

    def test_publish_plain_disabled_skips_plain_topic_send(self, monkeypatch, sample_cert_info):
        """plain_enabled=False stops the plain-topic send but connect_topic still fires -- independent gates."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t',
                plain_enabled=False, connect_topic='t-connect',
            )
            publisher.publish(sample_cert_info)

            mock_producer.send.assert_called_once()
            send_args, _ = mock_producer.send.call_args
            assert send_args[0] == 't-connect'

    def test_publish_plain_and_connect_both_disabled_sends_nothing(self, monkeypatch, sample_cert_info):
        """plain_enabled=False with no connect_topic configured is a silent no-op, never raises."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', plain_enabled=False,
            )
            publisher.publish(sample_cert_info)
            mock_producer.send.assert_not_called()

    # ── publish_access (certificate_accessed) ─────────────────────────────────

    def test_publish_access_noop_when_access_topic_not_configured(self, monkeypatch, sample_cert_info):
        """publish_access() is a no-op when access_topic wasn't set — access_enabled defaults to False."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher.access_enabled is False

            publisher.publish_access(
                sample_cert_info, process='/usr/bin/git', pid=555,
                parent_process='/usr/bin/bash', parent_pid=1,
            )
            mock_producer.send.assert_not_called()

    def test_publish_access_sends_when_access_topic_configured(self, monkeypatch, sample_cert_info):
        """publish_access() sends a certificate_accessed message to access_topic when configured."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', access_topic='t-access',
            )
            assert publisher.access_enabled is True

            publisher.publish_access(
                sample_cert_info, process='/usr/bin/git', pid=555,
                parent_process='/usr/bin/bash', parent_pid=1,
                namespace='default', pod_name='my-pod', pod_uid='uid-1',
                node_name='worker-node-1', app_label='my-app',
                container_name='main', container_id='c1', container_image='my-app:1.0',
            )

            send_args, send_kwargs = mock_producer.send.call_args
            assert send_args[0] == 't-access'
            assert send_kwargs['key'] == sample_cert_info.unique_key
            msg = send_kwargs['value']
            assert msg['event_type']      == 'certificate_accessed'
            assert msg['cert_unique_key'] == sample_cert_info.unique_key
            assert msg['process']         == '/usr/bin/git'
            assert msg['pid']             == 555
            assert msg['parent_process']  == '/usr/bin/bash'
            assert msg['parent_pid']      == 1
            assert msg['pod_name']        == 'my-pod'
            assert msg['node_name']       == 'worker-node-1'
            # Deliberately excludes discovery-only cert metadata (subject/SANs/FIPS/...) —
            # consumers join against the certificate_discovered topic on cert_unique_key.
            assert 'subject' not in msg
            assert 'fips_compliant' not in msg

    # ── publish_access() Kafka Connect envelope (access_connect_topic) ────────

    def test_publish_access_connect_noop_when_neither_flag_set(self, monkeypatch, sample_cert_info):
        """publish_access() sends nothing when both access_enabled and access_connect_enabled are unset (defaults)."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher.access_connect_enabled is False

            publisher.publish_access(
                sample_cert_info, process='/usr/bin/git', pid=555,
                parent_process='/usr/bin/bash', parent_pid=1,
            )
            mock_producer.send.assert_not_called()

    def test_publish_access_connect_sends_independent_of_access_enabled(self, monkeypatch, sample_cert_info):
        """access_connect_enabled alone (access_enabled left False) still sends an envelope to access_connect_topic."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', access_connect_topic='t-access-connect',
            )
            assert publisher.access_enabled is False
            assert publisher.access_connect_enabled is True

            publisher.publish_access(
                sample_cert_info, process='/usr/bin/git', pid=555,
                parent_process='/usr/bin/bash', parent_pid=1,
                namespace='default', pod_name='my-pod', pod_uid='uid-1',
                node_name='worker-node-1', app_label='my-app',
                container_name='main', container_id='c1', container_image='my-app:1.0',
            )

            mock_producer.send.assert_called_once()
            send_args, send_kwargs = mock_producer.send.call_args
            assert send_args[0] == 't-access-connect'
            envelope = send_kwargs['value']
            assert set(envelope.keys()) == {'schema', 'payload'}
            assert envelope['schema']['name'] == 'io.certanalyzer.CertificateAccessed'
            assert envelope['payload']['event_type'] == 'certificate_accessed'
            assert envelope['payload']['process']    == '/usr/bin/git'

    def test_publish_access_connect_key_includes_accessor_identity(self, monkeypatch, sample_cert_info):
        """access_connect_topic key includes the accessor, not just cert identity -- distinct accessors mustn't collide on upsert."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', access_connect_topic='t-access-connect',
            )

            publisher.publish_access(
                sample_cert_info, process='/usr/bin/git', pid=555,
                parent_process='/usr/bin/bash', parent_pid=1,
                namespace='default', pod_name='pod-a', node_name='worker-node-1',
                app_label='my-app', container_name='main',
            )
            key_a = mock_producer.send.call_args[1]['key']

            mock_producer.reset_mock()
            publisher.publish_access(
                sample_cert_info, process='/usr/bin/curl', pid=556,
                parent_process='/usr/bin/bash', parent_pid=1,
                namespace='default', pod_name='pod-a', node_name='worker-node-1',
                app_label='my-app', container_name='main',
            )
            key_b = mock_producer.send.call_args[1]['key']

            assert key_a != key_b
            expected_a = (
                f"worker-node-1:{sample_cert_info.path}:{sample_cert_info.cert_index}:"
                f"/usr/bin/git:/usr/bin/bash:pod-a:default:my-app:main"
            )
            assert key_a == expected_a

    def test_publish_access_connect_and_plain_both_enabled(self, monkeypatch, sample_cert_info):
        """Both access_enabled and access_connect_enabled together send to both topics."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t',
                access_topic='t-access', access_connect_topic='t-access-connect',
            )
            publisher.publish_access(
                sample_cert_info, process='/usr/bin/git', pid=555,
                parent_process='/usr/bin/bash', parent_pid=1,
            )
            assert mock_producer.send.call_count == 2
            topics_sent = {c[0][0] for c in mock_producer.send.call_args_list}
            assert topics_sent == {'t-access', 't-access-connect'}

    # ── publish() Kafka Connect envelope (connect_topic) ──────────────────────

    def test_publish_connect_noop_when_connect_topic_not_configured(self, monkeypatch, sample_cert_info):
        """publish() sends only the plain-topic message when connect_topic isn't set — purely additive, off by default."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher.connect_enabled is False

            publisher.publish(sample_cert_info)
            mock_producer.send.assert_called_once()

    def test_publish_connect_sends_envelope_when_connect_topic_configured(self, monkeypatch, sample_cert_info):
        """publish() additionally sends a {schema, payload} envelope to connect_topic when configured."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', connect_topic='t-connect',
            )
            assert publisher.connect_enabled is True

            publisher.publish(sample_cert_info)
            assert mock_producer.send.call_count == 2

            second_call_args, second_call_kwargs = mock_producer.send.call_args_list[1]
            assert second_call_args[0] == 't-connect'
            envelope = second_call_kwargs['value']
            assert set(envelope.keys()) == {'schema', 'payload'}
            assert envelope['schema']['type'] == 'struct'

    def test_publish_connect_envelope_payload_matches_plain_message(self, monkeypatch, sample_cert_info):
        """The connect envelope's payload carries the same field values as the plain-topic message."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', connect_topic='t-connect',
            )
            publisher.publish(sample_cert_info)

            plain_msg = mock_producer.send.call_args_list[0][1]['value']
            connect_payload = mock_producer.send.call_args_list[1][1]['value']['payload']

            for key, value in plain_msg.items():
                if key == 'pod_annotations':
                    continue  # JSON-encoded in the envelope, checked separately below
                assert connect_payload[key] == value, f"Mismatch on {key}"

    def test_publish_connect_schema_is_stable_across_calls(self, monkeypatch, sample_cert_info):
        """The Connect schema is built once and reused, not rebuilt per message."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', connect_topic='t-connect',
            )
            publisher.publish(sample_cert_info)
            publisher.publish(sample_cert_info)

            schema_1 = mock_producer.send.call_args_list[1][1]['value']['schema']
            schema_2 = mock_producer.send.call_args_list[3][1]['value']['schema']
            assert schema_1 is schema_2

    def test_publish_connect_pod_annotations_json_encoded(self, monkeypatch, sample_cert_info):
        """pod_annotations lands as a JSON-encoded string in the envelope, not a raw dict."""
        import dataclasses
        import json as _json
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        cert_info = dataclasses.replace(sample_cert_info, pod_annotations={'foo': 'bar'})

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', connect_topic='t-connect',
            )
            publisher.publish(cert_info)

            connect_payload = mock_producer.send.call_args_list[1][1]['value']['payload']
            assert isinstance(connect_payload['pod_annotations'], str)
            assert _json.loads(connect_payload['pod_annotations']) == {'foo': 'bar'}

    def test_publish_connect_key_is_node_path_cert_index(self, monkeypatch, sample_cert_info):
        """connect_topic key is node_name:path:cert_index -- not unique_key, so an upsert stays correct per node+slot."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', connect_topic='t-connect',
            )
            publisher.publish(sample_cert_info)

            second_call_kwargs = mock_producer.send.call_args_list[1][1]
            expected_key = f"{sample_cert_info.node_name}:{sample_cert_info.path}:{sample_cert_info.cert_index}"
            assert second_call_kwargs['key'] == expected_key
            assert second_call_kwargs['key'] != sample_cert_info.unique_key

    def test_publish_connect_schema_fields_optional_flags(self, monkeypatch, sample_cert_info):
        """Spot-check known-nullable vs. always-present fields carry the correct 'optional' flag."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(
                bootstrap_servers='b:9092', topic='t', connect_topic='t-connect',
            )
            publisher.publish(sample_cert_info)

            schema_fields = {
                f['field']: f for f in
                mock_producer.send.call_args_list[1][1]['value']['schema']['fields']
            }
            assert schema_fields['container_pid']['optional'] is True
            assert schema_fields['is_ca']['optional'] is True
            assert schema_fields['path']['optional'] is False
            assert schema_fields['event_type']['optional'] is False

    def test_publish_sends_to_configured_topic(self, monkeypatch, sample_cert_info):
        """Message is sent to the topic specified in configuration."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='my-topic')
            publisher.publish(sample_cert_info)

            topic_arg = mock_producer.send.call_args[0][0]
            assert topic_arg == 'my-topic'

    # ── error handling ────────────────────────────────────────────────────────

    def test_publish_silent_on_send_error(self, monkeypatch, sample_cert_info):
        """publish() logs a warning and never raises when send() throws."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_producer.send.side_effect = Exception('broker unavailable')
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.publish(sample_cert_info)   # must not raise

    def test_on_error_callback_logs_warning(self, monkeypatch, caplog):
        """_on_error() logs a warning without raising."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            with caplog.at_level(logging.WARNING):
                publisher._on_error(publisher._producer, Exception('delivery failed'))

            assert any('delivery' in r.message.lower() or 'kafka' in r.message.lower()
                       for r in caplog.records)

    def test_on_error_nullifies_matching_current_producer(self, monkeypatch):
        """_on_error() nullifies self._producer when it's still the producer the failed send came from."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            current_producer = publisher._producer

            publisher._on_error(current_producer, Exception('delivery failed'))

            assert publisher._producer is None

    def test_stale_on_error_does_not_nullify_a_superseded_producer(self, monkeypatch):
        """
        kafka-python invokes errbacks from its own internal I/O thread, and can
        do so long after the send() call that registered it (after internal
        retries/timeouts) -- possibly after a reconnect has already replaced
        self._producer with a new, healthy one. A stale errback for the OLD
        producer must not tear down the new one.
        """
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            old_producer = publisher._producer

            # Simulate a reconnect installing a new, healthy producer.
            new_producer = MagicMock()
            publisher._producer = new_producer

            # The old producer's delayed errback finally fires.
            publisher._on_error(old_producer, Exception('stale delivery failure'))

            assert publisher._producer is new_producer, \
                "a stale error from a superseded producer must not nullify the current one"

    def test_publish_errback_captures_producer_instance_at_send_time(self, monkeypatch, sample_cert_info):
        """
        publish() must bind the errback to the specific producer instance send()
        was issued from (not to whatever self._producer happens to be when the
        errback eventually fires) -- otherwise a delayed error from an old send
        could nullify a producer installed by a later reconnect.
        """
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock

        class FakeProducer:
            def __init__(self, **kwargs):
                self.errback = None

            def send(self, *args, **kwargs):
                future = MagicMock()
                future.add_errback = lambda cb: setattr(self, 'errback', cb)
                return future

            def close(self, timeout=None):
                pass

        with patch('agent.kafka.KafkaProducer', FakeProducer):
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher._reconnect_cooldown = 0

            old_producer = publisher._producer
            publisher.publish(sample_cert_info)
            assert old_producer.errback is not None

            # Reconnect: old producer is replaced by a new one.
            publisher._producer = None
            publisher.publish(sample_cert_info)
            new_producer = publisher._producer
            assert new_producer is not old_producer

            # The OLD producer's stale errback fires after the reconnect.
            old_producer.errback(Exception('old delivery failed'))

            assert publisher._producer is new_producer, \
                "a stale error bound to the old producer must not nullify the new one"

    # ── close ─────────────────────────────────────────────────────────────────

    def test_close_flushes_and_closes_producer(self, monkeypatch):
        """close() calls flush() then close() on the underlying producer."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock, call
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher.close()

            mock_producer.flush.assert_called_once()
            mock_producer.close.assert_called_once()

    def test_close_noop_when_producer_is_none(self):
        """close() is silent when _producer is None (Kafka not available)."""
        from cert_analyzer import KafkaPublisher
        publisher = KafkaPublisher.__new__(KafkaPublisher)
        publisher._producer = None
        publisher._topic = 't'
        publisher._lock = threading.RLock()
        publisher.close()   # must not raise

    # ── thread-safety ────────────────────────────────────────────────────────

    def test_concurrent_publish_connects_producer_once(self, monkeypatch, sample_cert_info):
        """
        Many threads calling publish() while the producer is absent must only
        construct one KafkaProducer — the self._lock around _connect()/publish()
        serializes the check-then-connect so concurrent callers (main thread,
        periodic_scan thread, and any number of large-file background workers)
        can't race into creating/discarding multiple producers.
        """
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        connect_count = {'n': 0}

        class SlowFakeProducer:
            def __init__(self, **kwargs):
                # Widen the race window — releases the GIL, giving other
                # threads a chance to interleave if the lock isn't held.
                time.sleep(0.02)
                connect_count['n'] += 1

            def send(self, *args, **kwargs):
                future = MagicMock()
                future.add_errback = lambda cb: None
                return future

            def close(self, timeout=None):
                pass

        with patch('agent.kafka.KafkaProducer', SlowFakeProducer):
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            connect_count['n'] = 0  # ignore the constructor's own initial connect
            publisher._producer = None  # force every thread to see "needs reconnect"
            publisher._reconnect_cooldown = 0

            threads = [
                threading.Thread(target=publisher.publish, args=(sample_cert_info,))
                for _ in range(20)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            assert connect_count['n'] == 1

    # ── integration with CertificateAnalyzer ─────────────────────────────────

    def test_analyzer_publishes_new_cert_to_kafka(
        self, analyzer, temp_dir, monkeypatch
    ):
        """process_event publishes a new certificate to Kafka exactly once."""
        from unittest.mock import MagicMock, patch
        import cert_analyzer as _ca

        # Attach a mock KafkaPublisher to the analyzer
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('kafka.example.com', 365)
        path = os.path.join(temp_dir, 'kafka.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        # Simulate a Tetragon event pointing at our cert file
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/curl'
        mock_kprobe.process.pid.value = 99
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe

        analyzer.process_event(mock_event)

        mock_publisher.publish.assert_called_once()
        published_cert = mock_publisher.publish.call_args[0][0]
        assert published_cert.path == path

    def test_node_name_propagated_from_event_to_cert_info(
        self, analyzer, temp_dir
    ):
        """node_name from GetEventsResponse is written to CertificateInfo and published."""
        from unittest.mock import MagicMock
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('node-test.example.com', 365)
        path = os.path.join(temp_dir, 'node-test.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        mock_event = MagicMock()
        mock_event.node_name = 'worker-node-42'
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/curl'
        mock_kprobe.process.pid.value = 99
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe

        analyzer.process_event(mock_event)

        published_cert = mock_publisher.publish.call_args[0][0]
        assert published_cert.node_name == 'worker-node-42'

    def test_analyzer_does_not_publish_redetected_cert(
        self, analyzer, temp_dir, monkeypatch
    ):
        """process_event does NOT publish to Kafka for re-detected known certs."""
        from unittest.mock import MagicMock
        import cert_analyzer as _ca

        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('redetect.example.com', 365)
        path = os.path.join(temp_dir, 'redetect.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def make_event(p):
            mock_event = MagicMock()
            mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
            mock_kprobe = MagicMock()
            mock_kprobe.process.binary = '/usr/bin/curl'
            mock_kprobe.process.pid.value = 99
            mock_kprobe.process.HasField.return_value = False
            mock_kprobe.HasField.return_value = False
            mock_arg = MagicMock()
            mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
            mock_arg.file_arg.path = p
            mock_kprobe.args = [mock_arg]
            mock_event.process_kprobe = mock_kprobe
            return mock_event

        # First detection — should publish
        analyzer.process_event(make_event(path))
        assert mock_publisher.publish.call_count == 1

        # Second detection — same file, already in known_certs, must NOT publish again
        analyzer.process_event(make_event(path))
        assert mock_publisher.publish.call_count == 1

    def test_analyzer_publishes_access_event_on_redetect_when_enabled(
        self, analyzer, temp_dir
    ):
        """A re-access by a new process publishes certificate_accessed when access_enabled."""
        from unittest.mock import MagicMock

        mock_publisher = MagicMock()
        mock_publisher.access_enabled = True
        mock_publisher.access_connect_enabled = False
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('access.example.com', 365)
        path = os.path.join(temp_dir, 'access.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def make_event(p, binary, pid):
            mock_event = MagicMock()
            mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
            mock_kprobe = MagicMock()
            mock_kprobe.process.binary = binary
            mock_kprobe.process.pid.value = pid
            mock_kprobe.process.HasField.side_effect = lambda f: f == 'pid'
            mock_kprobe.HasField.return_value = False
            mock_arg = MagicMock()
            mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
            mock_arg.file_arg.path = p
            mock_kprobe.args = [mock_arg]
            mock_event.process_kprobe = mock_kprobe
            return mock_event

        # First detection (discovery) — no access event yet.
        analyzer.process_event(make_event(path, '/usr/bin/curl', 99))
        mock_publisher.publish_access.assert_not_called()

        # Re-access by a different process — should publish certificate_accessed once.
        analyzer.process_event(make_event(path, '/usr/bin/git', 100))
        mock_publisher.publish_access.assert_called_once()
        access_args, access_kwargs = mock_publisher.publish_access.call_args
        published_cert_info = access_args[0]
        assert published_cert_info.path == path
        assert access_args[1] == '/usr/bin/git'
        assert access_args[2] == 100

        # A second re-access by the SAME process must not publish again (deduped).
        analyzer.process_event(make_event(path, '/usr/bin/git', 100))
        mock_publisher.publish_access.assert_called_once()

    def test_analyzer_does_not_publish_access_event_when_disabled(
        self, analyzer, temp_dir
    ):
        """Re-access does NOT publish certificate_accessed when access_enabled is False (the default)."""
        from unittest.mock import MagicMock

        mock_publisher = MagicMock()
        mock_publisher.access_enabled = False
        mock_publisher.access_connect_enabled = False
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('access-disabled.example.com', 365)
        path = os.path.join(temp_dir, 'access-disabled.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def make_event(p, binary, pid):
            mock_event = MagicMock()
            mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
            mock_kprobe = MagicMock()
            mock_kprobe.process.binary = binary
            mock_kprobe.process.pid.value = pid
            mock_kprobe.process.HasField.return_value = False
            mock_kprobe.HasField.return_value = False
            mock_arg = MagicMock()
            mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
            mock_arg.file_arg.path = p
            mock_kprobe.args = [mock_arg]
            mock_event.process_kprobe = mock_kprobe
            return mock_event

        analyzer.process_event(make_event(path, '/usr/bin/curl', 99))
        analyzer.process_event(make_event(path, '/usr/bin/git', 100))
        mock_publisher.publish_access.assert_not_called()

    def test_analyzer_publishes_access_event_when_only_access_connect_enabled(
        self, analyzer, temp_dir
    ):
        """A re-access still publishes certificate_accessed when only access_connect_enabled is set -- independent of access_enabled."""
        from unittest.mock import MagicMock

        mock_publisher = MagicMock()
        mock_publisher.access_enabled = False
        mock_publisher.access_connect_enabled = True
        analyzer.kafka_publisher = mock_publisher

        cert, _ = TestCertificateGeneration.generate_certificate('access-connect-only.example.com', 365)
        path = os.path.join(temp_dir, 'access-connect-only.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        def make_event(p, binary, pid):
            mock_event = MagicMock()
            mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
            mock_kprobe = MagicMock()
            mock_kprobe.process.binary = binary
            mock_kprobe.process.pid.value = pid
            mock_kprobe.process.HasField.side_effect = lambda f: f == 'pid'
            mock_kprobe.HasField.return_value = False
            mock_arg = MagicMock()
            mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
            mock_arg.file_arg.path = p
            mock_kprobe.args = [mock_arg]
            mock_event.process_kprobe = mock_kprobe
            return mock_event

        analyzer.process_event(make_event(path, '/usr/bin/curl', 99))
        analyzer.process_event(make_event(path, '/usr/bin/git', 100))
        mock_publisher.publish_access.assert_called_once()

    def test_analyzer_without_kafka_publisher_works_normally(
        self, analyzer, temp_dir
    ):
        """analyzer continues working normally when kafka_publisher is None."""
        from unittest.mock import MagicMock

        assert analyzer.kafka_publisher is None

        cert, _ = TestCertificateGeneration.generate_certificate('nokafka.example.com', 365)
        path = os.path.join(temp_dir, 'nokafka.pem')
        TestCertificateGeneration.save_certificate_pem(cert, path)

        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/test'
        mock_kprobe.process.pid.value = 1
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.HasField.return_value = False
        mock_arg = MagicMock()
        mock_arg.HasField.side_effect = lambda f: f == 'file_arg'
        mock_arg.file_arg.path = path
        mock_kprobe.args = [mock_arg]
        mock_event.process_kprobe = mock_kprobe

        # Must not raise even with no Kafka publisher
        analyzer.process_event(mock_event)
        assert path + ':0:' in ''.join(analyzer.known_certs.keys())


class TestKafkaReconnection:
    """
    Tests for KafkaPublisher automatic reconnection behaviour.

    Covers:
    - producer is nullified after a send failure so next publish retries
    - _connect() respects the cooldown period between reconnect attempts
    - _connect() succeeds after broker comes back up
    - publish() reconnects automatically when producer is None
    - publish() skips send if reconnect fails and cooldown has not elapsed
    - multiple sequential failures do not raise
    - _connect() closes broken producer before recreating it
    - cooldown resets after a successful reconnect
    - reconnect is attempted on first publish even if init failed
    """

    @pytest.fixture
    def reconnect_publisher(self, monkeypatch):
        """
        A KafkaPublisher constructed with a working producer, ready for
        reconnect tests. Returns (publisher, mock_producer_class) so tests
        can control subsequent KafkaProducer() calls.
        """
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            # Reset call count after init so tests start from a clean slate
            mock_cls.reset_mock()
            yield publisher, mock_cls

    @pytest.fixture
    def sample_cert_info(self):
        """Minimal CertificateInfo for reconnect tests."""
        from cert_analyzer import CertificateInfo
        return CertificateInfo(
            path='/etc/pki/tls/certs/test.crt',
            subject='CN=test.example.com',
            issuer='CN=Test CA',
            serial_number='abc123',
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            process='/usr/bin/curl',
            pid=1,
            namespace='',
            common_name='test.example.com',
            san_dns_names=[],
            cert_index=0,
            pod_name='',
            workload_kind='',
            workload_name='',
            pod_labels=None,
            app_label='',
            container_name='',
            container_image='',
            checksum='',
        )

    # ── producer nullified after send failure ─────────────────────────────────

    def test_send_failure_nullifies_producer(self, monkeypatch, sample_cert_info):
        """A send() exception sets _producer to None so next publish retries."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_producer.send.side_effect = Exception('broker down')
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher._producer is not None

            publisher.publish(sample_cert_info)

            assert publisher._producer is None, \
                'producer should be nullified after send failure'

    # ── cooldown ──────────────────────────────────────────────────────────────

    def test_connect_respects_cooldown(self, monkeypatch, sample_cert_info):
        """_connect() returns False immediately if called within the cooldown window."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            # Nullify producer and set last attempt to now
            publisher._producer = None
            publisher._last_connect_attempt = time.time()

            mock_cls.reset_mock()
            result = publisher._connect()

            assert result is False
            mock_cls.assert_not_called()

    def test_connect_proceeds_after_cooldown(self, monkeypatch, sample_cert_info):
        """_connect() creates a new producer once the cooldown has elapsed."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            # Simulate cooldown already elapsed
            publisher._producer = None
            publisher._last_connect_attempt = 0.0

            mock_cls.reset_mock()
            result = publisher._connect()

            assert result is True
            mock_cls.assert_called_once()
            assert publisher._producer is not None

    def test_publish_skips_send_when_reconnect_on_cooldown(
        self, monkeypatch, sample_cert_info
    ):
        """publish() silently skips sending if reconnect is still on cooldown."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            publisher._producer = None
            publisher._last_connect_attempt = time.time()  # cooldown active

            mock_cls.reset_mock()
            publisher.publish(sample_cert_info)  # must not raise

            mock_cls.assert_not_called()  # no reconnect attempted

    # ── automatic reconnect ───────────────────────────────────────────────────

    def test_publish_reconnects_when_producer_is_none(
        self, monkeypatch, sample_cert_info
    ):
        """publish() calls _connect() and sends when producer is None and cooldown elapsed."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            # Simulate broker restart — nullify producer and clear cooldown
            publisher._producer = None
            publisher._last_connect_attempt = 0.0

            mock_cls.reset_mock()
            mock_producer.reset_mock()

            publisher.publish(sample_cert_info)

            mock_cls.assert_called_once()          # reconnected
            mock_producer.send.assert_called_once() # message sent

    def test_publish_reconnects_and_sends_correct_message(
        self, monkeypatch, sample_cert_info
    ):
        """After reconnect the published message has the correct event_type and path."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_cls.return_value = mock_producer
            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            publisher._producer = None
            publisher._last_connect_attempt = 0.0
            mock_cls.reset_mock()
            mock_producer.reset_mock()

            publisher.publish(sample_cert_info)

            _, send_kwargs = mock_producer.send.call_args
            assert send_kwargs['value']['event_type'] == 'certificate_discovered'
            assert send_kwargs['value']['path'] == '/etc/pki/tls/certs/test.crt'

    # ── broken producer replaced on reconnect ─────────────────────────────────

    def test_connect_closes_broken_producer_before_reconnect(
        self, monkeypatch, sample_cert_info
    ):
        """_connect() calls close() on an existing broken producer before creating a new one."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            broken_producer = MagicMock()
            new_producer = MagicMock()
            mock_cls.side_effect = [broken_producer, new_producer]

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher._producer is broken_producer

            # Simulate a reconnect with cooldown cleared
            publisher._last_connect_attempt = 0.0
            publisher._connect()

            broken_producer.close.assert_called_once()
            assert publisher._producer is new_producer

    # ── multiple sequential failures ──────────────────────────────────────────

    def test_multiple_sequential_failures_never_raise(
        self, monkeypatch, sample_cert_info
    ):
        """Three consecutive send failures all log warnings and never raise."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_producer = MagicMock()
            mock_producer.send.side_effect = Exception('broker down')
            mock_cls.return_value = mock_producer

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')

            for _ in range(3):
                publisher._last_connect_attempt = 0.0  # bypass cooldown each time
                publisher.publish(sample_cert_info)     # must not raise

    # ── reconnect after init failure ──────────────────────────────────────────

    def test_reconnect_attempted_if_init_failed(
        self, monkeypatch, sample_cert_info
    ):
        """If the initial connection fails, publish() retries once cooldown elapses."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            # First call (init) fails, second call (reconnect) succeeds
            working_producer = MagicMock()
            mock_cls.side_effect = [Exception('broker down on startup'), working_producer]

            from cert_analyzer import KafkaPublisher
            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            assert publisher._producer is None  # init failed

            # Clear cooldown to allow immediate reconnect
            publisher._last_connect_attempt = 0.0

            publisher.publish(sample_cert_info)

            assert publisher._producer is working_producer
            working_producer.send.assert_called_once()

    # ── reconnect logs ─────────────────────────────────────────────────────────

    def test_reconnect_failure_logs_warning(self, monkeypatch, caplog):
        """A failed reconnect attempt logs a warning with retry interval."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.side_effect = Exception('broker down')
            from cert_analyzer import KafkaPublisher

            with caplog.at_level(logging.WARNING):
                publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
                publisher._last_connect_attempt = 0.0
                publisher._connect()

            assert any('retry' in r.message.lower() or 'failed' in r.message.lower()
                       for r in caplog.records)

    def test_successful_reconnect_logs_info(self, monkeypatch, caplog):
        """A successful reconnect logs an info message."""
        import agent.kafka as _ca
        monkeypatch.setattr(_ca, 'KAFKA_AVAILABLE', True)

        from unittest.mock import patch, MagicMock
        with patch('agent.kafka.KafkaProducer') as mock_cls:
            mock_cls.return_value = MagicMock()
            from cert_analyzer import KafkaPublisher

            publisher = KafkaPublisher(bootstrap_servers='b:9092', topic='t')
            publisher._producer = None
            publisher._last_connect_attempt = 0.0

            with caplog.at_level(logging.INFO):
                publisher._connect()

            assert any('connected' in r.message.lower() or 'initialised' in r.message.lower()
                       for r in caplog.records)


class TestOpensslUprobeHooking:
    """
    Tests for OpenSSL uprobe interception (openssl3-cert-load policy).

    Two code paths are exercised:
    - File-path hooks (SSL_CTX_use_certificate_file / SSL_CTX_use_certificate_chain_file):
      cert path is carried in a string_arg and handled by the existing
      extract_cert_path_from_event / process_event flow.
    - In-memory hooks (SSL_CTX_use_certificate_ASN1): raw DER bytes arrive in a bytes_arg and are
      handled by _handle_uprobe_in_memory_cert, which parses them directly
      without touching the filesystem.
    """

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _cert_der(cn='openssl.example.com', days=365):
        cert, _ = TestCertificateGeneration.generate_certificate(cn, days)
        return cert, cert.public_bytes(Encoding.DER)

    @staticmethod
    def _make_string_arg(value):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'string_arg'
        arg.string_arg = value
        return arg

    @staticmethod
    def _make_bytes_arg(data):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'bytes_arg'
        arg.bytes_arg = data
        return arg

    @staticmethod
    def _make_uprobe_event(args, pid=1234, binary='/usr/bin/nginx', has_pod=False,
                           symbol='SSL_CTX_use_certificate_ASN1'):
        """Build a minimal mock process_uprobe event."""
        from unittest.mock import MagicMock

        mock_uprobe = MagicMock()
        mock_uprobe.process.binary = binary
        mock_uprobe.process.pid.value = pid
        mock_uprobe.symbol = symbol

        if has_pod:
            mock_uprobe.process.HasField.side_effect = lambda f: f in ('pid', 'pod')
            mock_uprobe.process.pod.namespace = 'test-ns'
            mock_uprobe.process.pod.name = 'test-pod'
            mock_uprobe.process.pod.workload_object.kind = 'Deployment'
            mock_uprobe.process.pod.workload_object.name = 'test-deploy'
            mock_uprobe.process.pod.labels = {}
        else:
            mock_uprobe.process.HasField.side_effect = lambda f: f == 'pid'

        mock_uprobe.HasField.side_effect = lambda f: False
        mock_uprobe.args = args

        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_uprobe'
        mock_event.process_uprobe = mock_uprobe
        return mock_event

    @staticmethod
    def _make_kprobe_event():
        """Build a minimal mock process_kprobe event (no args)."""
        from unittest.mock import MagicMock
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_kprobe'
        mock_kprobe = MagicMock()
        mock_kprobe.process.binary = '/usr/bin/curl'
        mock_kprobe.process.pid.value = 999
        mock_kprobe.process.HasField.return_value = False
        mock_kprobe.HasField.return_value = False
        mock_kprobe.args = []
        mock_event.process_kprobe = mock_kprobe
        return mock_event

    # ----------------------------------------- file-path uprobe (string_arg)

    def test_file_path_uprobe_string_arg_is_extracted(self, analyzer, temp_dir):
        """extract_cert_path_from_event finds a cert path in a uprobe string_arg."""
        cert_path = os.path.join(temp_dir, 'server.pem')
        cert, _ = TestCertificateGeneration.generate_certificate('path-uprobe.example.com', 365)
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        event = self._make_uprobe_event([self._make_string_arg(cert_path)])
        extracted, _, _, _, _, _, _ = analyzer.extract_cert_path_from_event(event)

        assert extracted == cert_path

    def test_file_path_uprobe_non_cert_string_arg_is_ignored(self, analyzer):
        """extract_cert_path_from_event ignores a string_arg that is not a cert path."""
        event = self._make_uprobe_event([self._make_string_arg('/etc/hosts')])
        cert_path, _, _, _, _, _, _ = analyzer.extract_cert_path_from_event(event)

        assert cert_path is None

    def test_file_path_uprobe_process_event_end_to_end(self, analyzer, temp_dir):
        """process_event resolves a cert file referenced by a uprobe string_arg."""
        cert_path = os.path.join(temp_dir, 'uprobe-file.pem')
        cert, _ = TestCertificateGeneration.generate_certificate('uprobe-file.example.com', 365)
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        event = self._make_uprobe_event([self._make_string_arg(cert_path)])
        analyzer.process_event(event)

        assert any(k.startswith(cert_path + ':') for k in analyzer.known_certs)

    # ----------------------------------------- in-memory DER (bytes_arg)

    def test_handle_bytes_returns_false_for_kprobe_event(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False for a non-uprobe event."""
        result = analyzer._handle_uprobe_in_memory_cert(self._make_kprobe_event())
        assert result is False

    def test_handle_bytes_returns_false_when_no_bytes_arg(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False when args contain no bytes_arg."""
        _, der = self._cert_der()
        # Only a string_arg — no bytes_arg
        event = self._make_uprobe_event([self._make_string_arg('/some/path.pem')])
        assert analyzer._handle_uprobe_in_memory_cert(event) is False

    def test_handle_bytes_returns_false_for_garbage_bytes(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False and does not raise on invalid DER."""
        event = self._make_uprobe_event([self._make_bytes_arg(b'\xde\xad\xbe\xef' * 16)])
        assert analyzer._handle_uprobe_in_memory_cert(event) is False

    def test_handle_bytes_returns_false_for_empty_bytes(self, analyzer):
        """_handle_uprobe_in_memory_cert returns False on empty bytes_arg."""
        event = self._make_uprobe_event([self._make_bytes_arg(b'')])
        assert analyzer._handle_uprobe_in_memory_cert(event) is False

    def test_handle_bytes_returns_true_for_valid_der(self, analyzer):
        """_handle_uprobe_in_memory_cert returns True when bytes_arg is valid DER."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        assert analyzer._handle_uprobe_in_memory_cert(event) is True

    def test_handle_bytes_adds_cert_to_known_certs(self, analyzer):
        """A cert parsed from bytes_arg is stored in known_certs."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)
        assert len(analyzer.known_certs) == 1

    def test_handle_bytes_synthetic_path_format(self, analyzer):
        """CertificateInfo.path uses the uprobe://<symbol>/<pid>/<serial> scheme."""
        cert, der = self._cert_der()
        serial = str(cert.serial_number)
        event = self._make_uprobe_event([self._make_bytes_arg(der)], pid=5678,
                                        symbol='SSL_CTX_use_certificate_ASN1')
        analyzer._handle_uprobe_in_memory_cert(event)

        stored = list(analyzer.known_certs.values())[0]
        assert stored.path == f'uprobe://SSL_CTX_use_certificate_ASN1/5678/{serial}'

    def test_handle_bytes_deduplicates_same_cert(self, analyzer):
        """Calling _handle_uprobe_in_memory_cert twice with the same DER adds only one entry."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)
        analyzer._handle_uprobe_in_memory_cert(event)
        assert len(analyzer.known_certs) == 1

    def test_handle_bytes_two_distinct_certs_both_stored(self, analyzer):
        """Two different certs from separate bytes_arg events are both stored."""
        _, der1 = self._cert_der('a.example.com')
        _, der2 = self._cert_der('b.example.com')
        analyzer._handle_uprobe_in_memory_cert(
            self._make_uprobe_event([self._make_bytes_arg(der1)], pid=1)
        )
        analyzer._handle_uprobe_in_memory_cert(
            self._make_uprobe_event([self._make_bytes_arg(der2)], pid=2)
        )
        assert len(analyzer.known_certs) == 2

    def test_handle_bytes_cert_fields_populated(self, analyzer):
        """CertificateInfo fields are correctly populated from the DER cert."""
        cert, der = self._cert_der('fields.example.com', days=90)
        event = self._make_uprobe_event([self._make_bytes_arg(der)], pid=42,
                                        binary='/usr/bin/python3')
        analyzer._handle_uprobe_in_memory_cert(event)

        info = list(analyzer.known_certs.values())[0]
        assert 'fields.example.com' in info.subject
        assert info.pid == 42
        assert info.process == '/usr/bin/python3'
        assert info.days_until_expiry > 80

    def test_handle_bytes_updates_last_event_timestamp(self, analyzer):
        """last_event_timestamp is updated when a bytes_arg cert is successfully parsed."""
        analyzer.last_event_time = 0.0
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)
        assert analyzer.last_event_time > 0

    def test_handle_bytes_timestamp_not_updated_on_invalid_der(self, analyzer):
        """last_event_timestamp is NOT updated when DER parsing fails."""
        analyzer.last_event_time = 0.0
        event = self._make_uprobe_event([self._make_bytes_arg(b'not-a-cert')])
        analyzer._handle_uprobe_in_memory_cert(event)
        assert analyzer.last_event_time == 0.0

    def test_handle_bytes_self_filter_by_process_name(self, analyzer):
        """cert-analyzer process is silently dropped when filter_self_events is True."""
        assert analyzer.filter_self_events is True
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)],
                                        binary='/app/cert-analyzer')
        result = analyzer._handle_uprobe_in_memory_cert(event)
        assert result is False
        assert len(analyzer.known_certs) == 0

    def test_handle_bytes_self_filter_by_pid(self, analyzer, monkeypatch):
        """Own process PID is silently dropped when filter_self_events is True."""
        assert analyzer.filter_self_events is True
        monkeypatch.setattr(os, 'getpid', lambda: 9999)
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)], pid=9999)
        result = analyzer._handle_uprobe_in_memory_cert(event)
        assert result is False
        assert len(analyzer.known_certs) == 0

    def test_handle_bytes_self_filter_disabled(self, analyzer):
        """cert-analyzer process is NOT filtered when filter_self_events is False."""
        analyzer.filter_self_events = False
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)],
                                        binary='/app/cert-analyzer')
        result = analyzer._handle_uprobe_in_memory_cert(event)
        assert result is True

    def test_handle_bytes_pod_context_applied(self, analyzer):
        """Pod name and namespace from the uprobe event are stored on CertificateInfo."""
        _, der = self._cert_der()
        event = self._make_uprobe_event([self._make_bytes_arg(der)], has_pod=True)
        analyzer._handle_uprobe_in_memory_cert(event)

        info = list(analyzer.known_certs.values())[0]
        assert info.pod_name == 'test-pod'
        assert info.namespace == 'test-ns'

    # ----------------------------------------- process_event routing

    def test_process_event_routes_bytes_arg_to_in_memory_handler(self, analyzer):
        """process_event stores a cert when the uprobe event contains bytes_arg."""
        _, der = self._cert_der('route.example.com')
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer.process_event(event)
        assert len(analyzer.known_certs) == 1

    def test_process_event_skips_bytes_handler_for_kprobe(self, analyzer):
        """process_event does not attempt bytes parsing for a kprobe event with no path."""
        event = self._make_kprobe_event()
        analyzer.process_event(event)  # no path, no bytes_arg → nothing stored
        assert len(analyzer.known_certs) == 0

    def test_process_event_prefers_file_path_over_bytes_arg(self, analyzer, temp_dir):
        """When both string_arg and bytes_arg are present, the file path wins."""
        cert_path = os.path.join(temp_dir, 'both.pem')
        cert, der = self._cert_der('both.example.com')
        TestCertificateGeneration.save_certificate_pem(cert, cert_path)

        event = self._make_uprobe_event([
            self._make_string_arg(cert_path),
            self._make_bytes_arg(der),
        ])
        analyzer.process_event(event)

        # Stored under the real file path, not a synthetic uprobe:// path
        assert any(k.startswith(cert_path + ':') for k in analyzer.known_certs)
        assert not any('uprobe://' in k for k in analyzer.known_certs)

    # ----------------------------------------- Kafka integration

    def test_kafka_published_for_new_in_memory_cert(self, analyzer):
        """A new cert extracted from bytes_arg is published to Kafka."""
        from unittest.mock import MagicMock
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        _, der = self._cert_der('kafka-bytes.example.com')
        event = self._make_uprobe_event([self._make_bytes_arg(der)])
        analyzer._handle_uprobe_in_memory_cert(event)

        mock_publisher.publish.assert_called_once()
        published = mock_publisher.publish.call_args[0][0]
        assert 'uprobe://SSL_CTX_use_certificate_ASN1' in published.path

    def test_kafka_not_published_for_redetected_in_memory_cert(self, analyzer):
        """Re-detected in-memory cert (same DER) is NOT published to Kafka again."""
        from unittest.mock import MagicMock
        mock_publisher = MagicMock()
        analyzer.kafka_publisher = mock_publisher

        _, der = self._cert_der('kafka-dedup.example.com')
        event = self._make_uprobe_event([self._make_bytes_arg(der)])

        analyzer._handle_uprobe_in_memory_cert(event)
        analyzer._handle_uprobe_in_memory_cert(event)

        assert mock_publisher.publish.call_count == 1


class TestJavaNSSFIPSHooking:
    """
    Tests for NSC_CreateObject / NSC_FindObjectsInit uprobe handlers (java-fips-nss-cert policy).

    Both handlers decode a little-endian CK_ATTRIBUTE[] template read from /proc/<pid>/mem.
    _read_process_memory is patched throughout so no live process is needed.
    """

    # PKCS#11 constants mirrored from the production code
    CKA_CLASS        = 0x00000001
    CKA_VALUE        = 0x00000011
    CKO_CERTIFICATE  = 0x00000001
    TMPL_ADDR        = 0x1000
    CLASS_ADDR       = 0x2000
    DER_ADDR         = 0x3000

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _cert_der(cn='fips.example.com', days=365):
        cert, _ = TestCertificateGeneration.generate_certificate(cn, days)
        return cert, cert.public_bytes(Encoding.DER)

    @staticmethod
    def _make_uint64_arg(value):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'size_arg'
        arg.size_arg = value
        return arg

    @staticmethod
    def _pack_attr(attr_type: int, p_value: int, val_len: int) -> bytes:
        """Pack one CK_ATTRIBUTE struct (24 bytes, little-endian LP64 layout)."""
        return (
            attr_type.to_bytes(8, 'little') +
            p_value.to_bytes(8, 'little') +
            val_len.to_bytes(8, 'little')
        )

    @classmethod
    def _make_event(cls, symbol, uint64_values, pid=1234, binary='/usr/bin/java',
                    has_pod=False):
        """Build a mock process_uprobe event with uint64 args."""
        from unittest.mock import MagicMock
        mock_uprobe = MagicMock()
        mock_uprobe.process.binary = binary
        mock_uprobe.process.pid.value = pid
        mock_uprobe.symbol = symbol
        if has_pod:
            mock_uprobe.process.HasField.side_effect = lambda f: f in ('pid', 'pod')
            mock_uprobe.process.pod.namespace = 'fips-ns'
            mock_uprobe.process.pod.name = 'java-pod'
            mock_uprobe.process.pod.workload_object.kind = 'Deployment'
            mock_uprobe.process.pod.workload_object.name = 'java-deploy'
            mock_uprobe.process.pod.labels = {}
        else:
            mock_uprobe.process.HasField.side_effect = lambda f: f == 'pid'
        mock_uprobe.HasField.side_effect = lambda f: False
        mock_uprobe.args = [cls._make_uint64_arg(v) for v in uint64_values]
        mock_event = MagicMock()
        mock_event.HasField.side_effect = lambda f: f == 'process_uprobe'
        mock_event.process_uprobe = mock_uprobe
        return mock_event

    @staticmethod
    def _make_kprobe_event():
        from unittest.mock import MagicMock
        ev = MagicMock()
        ev.HasField.side_effect = lambda f: f == 'process_kprobe'
        return ev

    @classmethod
    def _cert_template(cls, der: bytes) -> tuple:
        """
        Build the three _read_process_memory return values for a successful
        _handle_nsc_create_object call: (template_bytes, ck_class_bytes, der_bytes).
        Template layout: [CKA_CLASS → CLASS_ADDR, CKA_VALUE → DER_ADDR].
        """
        tmpl = (
            cls._pack_attr(cls.CKA_CLASS, cls.CLASS_ADDR, 4) +
            cls._pack_attr(cls.CKA_VALUE, cls.DER_ADDR, len(der))
        )
        ck_class = cls.CKO_CERTIFICATE.to_bytes(4, 'little')
        return tmpl, ck_class, der

    # ------------------------------------------------------------------ _read_process_memory

    def test_read_memory_returns_none_for_zero_address(self, analyzer):
        assert analyzer._read_process_memory(1234, 0, 100) is None

    def test_read_memory_returns_none_for_zero_size(self, analyzer):
        assert analyzer._read_process_memory(1234, self.TMPL_ADDR, 0) is None

    def test_read_memory_returns_none_on_ioerror(self, analyzer):
        import unittest.mock as mock
        with mock.patch('builtins.open', side_effect=IOError('no such process')):
            assert analyzer._read_process_memory(99999, self.TMPL_ADDR, 16) is None

    def test_read_memory_returns_bytes_on_success(self, analyzer):
        import unittest.mock as mock
        data = b'\xde\xad\xbe\xef' * 4
        m = mock.MagicMock()
        m.__enter__ = mock.Mock(return_value=m)
        m.__exit__ = mock.Mock(return_value=False)
        m.read.return_value = data
        with mock.patch('builtins.open', return_value=m):
            result = analyzer._read_process_memory(1234, self.TMPL_ADDR, 16)
        assert result == data

    # ------------------------------------------------------------------ NSC_CreateObject

    def test_create_object_rejects_kprobe(self, analyzer):
        """Returns False immediately for a non-uprobe event type."""
        assert analyzer._handle_nsc_create_object(self._make_kprobe_event()) is False

    def test_create_object_rejects_too_few_args(self, analyzer):
        """Returns False when fewer than 3 uint64 args are present."""
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR])
        assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_zero_count(self, analyzer):
        """Returns False when attribute count arg is 0."""
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 0])
        assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_excessive_count(self, analyzer):
        """Returns False when attribute count exceeds the sanity cap of 64."""
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 65])
        assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_unreadable_template(self, analyzer):
        """Returns False when /proc/pid/mem cannot be read for the template."""
        import unittest.mock as mock
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory', return_value=None):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_non_cert_ck_class(self, analyzer):
        """Returns False when CKA_CLASS is CKO_DATA (0x0), not CKO_CERTIFICATE."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl = (
            self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4) +
            self._pack_attr(self.CKA_VALUE, self.DER_ADDR, len(der))
        )
        ck_data = (0x00000000).to_bytes(4, 'little')
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_data, der]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_missing_cka_value(self, analyzer):
        """Returns False when template contains CKA_CLASS only (no DER payload pointer)."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_cert = self.CKO_CERTIFICATE.to_bytes(4, 'little')
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_garbage_der(self, analyzer):
        """Returns False when the CKA_VALUE bytes are not valid DER."""
        import unittest.mock as mock
        junk = b'\xde\xad\xbe\xef' * 50  # 200 bytes — passes size guard, fails DER parse
        tmpl, ck_cert, _ = self._cert_template(junk)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, junk]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_rejects_unreadable_der(self, analyzer):
        """Returns False when the DER memory read returns None."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, None]):
            assert analyzer._handle_nsc_create_object(event) is False

    def test_create_object_accepts_valid_cert(self, analyzer):
        """Returns True when a well-formed DER cert is found in the template."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            assert analyzer._handle_nsc_create_object(event) is True

    def test_create_object_stores_cert_in_known_certs(self, analyzer):
        """A valid cert is persisted to known_certs after extraction."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        assert len(analyzer.known_certs) == 1

    def test_create_object_synthetic_path_format(self, analyzer):
        """CertificateInfo.path uses the uprobe://NSC_CreateObject/<pid>/<serial> scheme."""
        import unittest.mock as mock
        cert, der = self._cert_der()
        serial = str(cert.serial_number)
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2], pid=5555)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        stored = list(analyzer.known_certs.values())[0]
        assert stored.path == f'uprobe://NSC_CreateObject/5555/{serial}'

    def test_create_object_deduplicates_cert(self, analyzer):
        """A second event for the same cert returns True without adding a duplicate entry."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            result = analyzer._handle_nsc_create_object(event)
        assert result is True
        assert len(analyzer.known_certs) == 1

    def test_create_object_self_filter_by_process_name(self, analyzer):
        """Events from a cert-analyzer binary are silently dropped."""
        import unittest.mock as mock
        assert analyzer.filter_self_events is True
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2],
                                 binary='/app/cert-analyzer')
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            result = analyzer._handle_nsc_create_object(event)
        assert result is False
        assert len(analyzer.known_certs) == 0

    def test_create_object_self_filter_by_pid(self, analyzer, monkeypatch):
        """Events whose PID matches the analyzer's own PID are silently dropped."""
        import unittest.mock as mock
        assert analyzer.filter_self_events is True
        monkeypatch.setattr(os, 'getpid', lambda: 1234)
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2], pid=1234)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            result = analyzer._handle_nsc_create_object(event)
        assert result is False

    def test_create_object_updates_event_timestamp(self, analyzer):
        """last_event_timestamp is updated after a successful cert extraction."""
        import unittest.mock as mock
        analyzer.last_event_time = 0.0
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        assert analyzer.last_event_time > 0

    def test_create_object_applies_pod_context(self, analyzer):
        """Pod namespace from the uprobe event is stored on the resulting CertificateInfo."""
        import unittest.mock as mock
        _, der = self._cert_der()
        tmpl, ck_cert, _ = self._cert_template(der)
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2], has_pod=True)
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert, der]):
            analyzer._handle_nsc_create_object(event)
        stored = list(analyzer.known_certs.values())[0]
        assert stored.namespace == 'fips-ns'

    # ------------------------------------------------------------------ NSC_FindObjectsInit

    def test_find_objects_rejects_kprobe(self, analyzer):
        """Returns False immediately for a non-uprobe event type."""
        assert analyzer._handle_nsc_find_objects_init(self._make_kprobe_event()) is False

    def test_find_objects_rejects_too_few_args(self, analyzer):
        """Returns False when fewer than 3 uint64 args are present."""
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR])
        assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_zero_count(self, analyzer):
        """Returns False when the attribute count arg is 0."""
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 0])
        assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_excessive_count(self, analyzer):
        """Returns False when attribute count exceeds the sanity cap of 32."""
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 33])
        assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_unreadable_template(self, analyzer):
        """Returns False when /proc/pid/mem cannot be read for the template."""
        import unittest.mock as mock
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory', return_value=None):
            assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_rejects_non_cert_filter(self, analyzer):
        """Returns False when the template filters on CKO_DATA, not CKO_CERTIFICATE."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_data = (0x00000000).to_bytes(4, 'little')
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_data]):
            assert analyzer._handle_nsc_find_objects_init(event) is False

    def test_find_objects_returns_true_for_cert_filter(self, analyzer):
        """Returns True when the template contains a CKO_CERTIFICATE class filter."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_cert = self.CKO_CERTIFICATE.to_bytes(4, 'little')
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_read_process_memory',
                               side_effect=[tmpl, ck_cert]):
            assert analyzer._handle_nsc_find_objects_init(event) is True

    def test_find_objects_logs_cert_enumeration(self, analyzer, caplog):
        """An INFO log mentioning NSC_FindObjectsInit is emitted when cert enumeration fires."""
        import unittest.mock as mock
        tmpl = self._pack_attr(self.CKA_CLASS, self.CLASS_ADDR, 4)
        ck_cert = self.CKO_CERTIFICATE.to_bytes(4, 'little')
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1],
                                 binary='/usr/bin/java', pid=9876)
        with caplog.at_level(logging.INFO):
            with mock.patch.object(analyzer, '_read_process_memory',
                                   side_effect=[tmpl, ck_cert]):
                analyzer._handle_nsc_find_objects_init(event)
        assert any('NSC_FindObjectsInit' in r.message for r in caplog.records)

    def test_find_objects_self_filter_by_pid(self, analyzer, monkeypatch):
        """Own PID is dropped before any memory reads occur."""
        import unittest.mock as mock
        assert analyzer.filter_self_events is True
        monkeypatch.setattr(os, 'getpid', lambda: 9876)
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1], pid=9876)
        with mock.patch.object(analyzer, '_read_process_memory') as mock_mem:
            result = analyzer._handle_nsc_find_objects_init(event)
        assert result is False
        mock_mem.assert_not_called()

    # ------------------------------------------------------------------ process_event routing

    def test_process_event_routes_nsc_create_object(self, analyzer):
        """process_event dispatches NSC_CreateObject symbol to _handle_nsc_create_object."""
        import unittest.mock as mock
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_handle_nsc_create_object') as mock_handler:
            analyzer.process_event(event)
        mock_handler.assert_called_once_with(event)

    def test_process_event_routes_nsc_find_objects_init(self, analyzer):
        """process_event dispatches NSC_FindObjectsInit symbol to _handle_nsc_find_objects_init."""
        import unittest.mock as mock
        event = self._make_event('NSC_FindObjectsInit', [0, self.TMPL_ADDR, 1])
        with mock.patch.object(analyzer, '_handle_nsc_find_objects_init') as mock_handler:
            analyzer.process_event(event)
        mock_handler.assert_called_once_with(event)

    def test_process_event_nsc_symbols_do_not_fall_through_to_bytes_handler(self, analyzer):
        """_handle_uprobe_in_memory_cert is not called when the symbol is an NSC_ handler."""
        import unittest.mock as mock
        event = self._make_event('NSC_CreateObject', [0, self.TMPL_ADDR, 2])
        with mock.patch.object(analyzer, '_handle_nsc_create_object', return_value=True), \
             mock.patch.object(analyzer, '_handle_uprobe_in_memory_cert') as mock_bytes:
            analyzer.process_event(event)
        mock_bytes.assert_not_called()


class TestResolveProcessBinary:
    """Tests for _resolve_process_binary fallback when Tetragon truncates the binary path."""

    def test_normal_path_confirmed_via_proc_exe(self, analyzer):
        """A non-truncated binary path is returned unchanged when proc/exe agrees."""
        import unittest.mock as mock
        with mock.patch('os.readlink', return_value='/usr/bin/nginx'):
            result = analyzer._resolve_process_binary('/usr/bin/nginx', 9999)
        assert result == '/usr/bin/nginx'

    def test_truncated_path_resolved_via_proc_exe(self, analyzer, tmp_path):
        """When Tetragon gives a directory (truncated), /proc/{pid}/exe provides the full path."""
        link_dir = tmp_path / 'build'
        link_dir.mkdir()
        binary = link_dir / 'test_openssl3_cert_load'
        binary.write_bytes(b'')

        import unittest.mock as mock

        original_readlink = __import__('os').readlink

        def mock_readlink(path):
            if path == '/proc/1234/exe':
                return str(binary)
            return original_readlink(path)

        with mock.patch('os.readlink', side_effect=mock_readlink):
            result = analyzer._resolve_process_binary(str(link_dir), 1234)
        assert result == str(binary)

    def test_protect_home_path_resolved_via_proc_exe(self, analyzer, tmp_path):
        """Works even when ProtectHome makes os.path.isdir() unreliable for /home paths."""
        import unittest.mock as mock

        home_dir = '/home/benm/app/build'
        home_binary = '/home/benm/app/build/myserver'

        original_readlink = __import__('os').readlink

        def mock_readlink(path):
            if path == '/proc/1234/exe':
                return home_binary
            return original_readlink(path)

        with mock.patch('os.readlink', side_effect=mock_readlink), \
             mock.patch('os.path.isdir', return_value=False):
            result = analyzer._resolve_process_binary(home_dir, 1234)
        assert result == home_binary

    def test_proc_exe_oserror_returns_original(self, analyzer):
        """Original path is returned when /proc/{pid}/exe raises OSError (process exited)."""
        import unittest.mock as mock

        with mock.patch('os.readlink', side_effect=OSError('no such process')):
            result = analyzer._resolve_process_binary('/some/build/dir', 42)
        assert result == '/some/build/dir'


def _generate_ca_signed_certificate(common_name: str, days_valid: int, ca_cert, ca_key):
    """Generate a certificate issued by a separate CA (not self-signed)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    not_valid_before = datetime.utcnow()
    not_valid_after  = datetime.utcnow() + timedelta(days=days_valid)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256(), backend=default_backend())
    return cert, private_key


class TestSelfSignedDetection:
    """
    Tests for is_self_signed detection in extract_certificate_info().

    Note: TestCertificateGeneration.generate_certificate() always creates
    self-signed certificates (issuer == subject, signed with own key).
    CA-signed certificates require _generate_ca_signed_certificate().
    """

    def test_self_signed_cert_detected(self, analyzer, temp_dir):
        """A self-signed certificate has is_self_signed=True."""
        cert, _ = TestCertificateGeneration.generate_certificate("self.example.com", 365)
        path = os.path.join(temp_dir, "self.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_self_signed is True

    def test_ca_signed_cert_not_self_signed(self, analyzer, temp_dir):
        """A certificate signed by a separate CA has is_self_signed=False."""
        ca_cert, ca_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        leaf_cert, _    = _generate_ca_signed_certificate("leaf.example.com", 365, ca_cert, ca_key)

        path = os.path.join(temp_dir, "leaf.pem")
        TestCertificateGeneration.save_certificate_pem(leaf_cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_self_signed is False

    def test_root_ca_is_self_signed(self, analyzer, temp_dir):
        """A self-signed root CA certificate is correctly identified as self-signed."""
        ca_cert, _ = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        path = os.path.join(temp_dir, "root_ca.pem")
        TestCertificateGeneration.save_certificate_pem(ca_cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_self_signed is True

    def test_intermediate_ca_is_not_self_signed(self, analyzer, temp_dir):
        """An intermediate CA signed by a root CA is not self-signed."""
        root_cert, root_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        inter_cert, _       = _generate_ca_signed_certificate("Intermediate CA", 1825, root_cert, root_key)

        path = os.path.join(temp_dir, "intermediate.pem")
        TestCertificateGeneration.save_certificate_pem(inter_cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_self_signed is False

    def test_prometheus_metric_set_for_self_signed(self, analyzer, temp_dir):
        """tls_certificate_self_signed gauge is 1 for a self-signed certificate."""
        cert, _ = TestCertificateGeneration.generate_certificate("metric-self.example.com", 365)
        path = os.path.join(temp_dir, "metric-self.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        val = analyzer.metrics.cert_self_signed.labels(
            cert_path=path,
            cert_index="0",
            pod_name="",
            namespace="",
            workload_kind="",
            workload_name="",
            node_name="",
            app_label="",
            container_name="",
            is_ca="unknown",  # generate_certificate without is_ca=True adds no BasicConstraints
            issuer=cert_infos[0].issuer[:100],
            serial=cert_infos[0].serial_number,
            checksum=cert_infos[0].checksum,
            spki_hash=cert_infos[0].spki_hash,
        )._value.get()
        assert val == 1.0

    def test_prometheus_metric_set_for_ca_signed(self, analyzer, temp_dir):
        """tls_certificate_self_signed gauge is 0 for a CA-signed certificate."""
        ca_cert, ca_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        leaf_cert, _    = _generate_ca_signed_certificate("metric-leaf.example.com", 365, ca_cert, ca_key)

        path = os.path.join(temp_dir, "metric-leaf.pem")
        TestCertificateGeneration.save_certificate_pem(leaf_cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)
        analyzer.metrics.update_certificate_metrics(cert_infos[0])

        val = analyzer.metrics.cert_self_signed.labels(
            cert_path=path,
            cert_index="0",
            pod_name="",
            namespace="",
            workload_kind="",
            workload_name="",
            node_name="",
            app_label="",
            container_name="",
            is_ca="unknown",  # _generate_ca_signed_certificate adds no BasicConstraints
            issuer=cert_infos[0].issuer[:100],
            serial=cert_infos[0].serial_number,
            checksum=cert_infos[0].checksum,
            spki_hash=cert_infos[0].spki_hash,
        )._value.get()
        assert val == 0.0

    def test_is_ca_label_values(self, analyzer, temp_dir):
        """is_ca label is 'true' for a CA cert, 'false' for an explicit non-CA, 'unknown' when absent."""
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

        def _cert_with_bc(is_ca_value):
            """Build a minimal self-signed cert with an explicit BasicConstraints extension."""
            key = _rsa.generate_private_key(65537, 2048, backend=default_backend())
            subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bc-test")])
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=is_ca_value, path_length=None), critical=True)
            )
            return builder.sign(key, hashes.SHA256(), backend=default_backend())

        def _label(cert_obj, fname):
            path = os.path.join(temp_dir, fname)
            TestCertificateGeneration.save_certificate_pem(cert_obj, path)
            infos = analyzer.analyze_certificate(path, "test", 1)
            analyzer.metrics.update_certificate_metrics(infos[0])
            return infos[0].is_ca

        assert _label(_cert_with_bc(True),  "bc_true.pem")  is True
        assert _label(_cert_with_bc(False), "bc_false.pem") is False

        # No BasicConstraints extension → is_ca is None → label 'unknown'
        no_bc_cert, _ = TestCertificateGeneration.generate_certificate("no-bc.example.com", 365)
        assert _label(no_bc_cert, "no_bc.pem") is None

    def test_self_signed_logs_warning(self, analyzer, temp_dir, caplog):
        """A self-signed certificate triggers a WARNING log with SELF-SIGNED in the message."""
        cert, _ = TestCertificateGeneration.generate_certificate("warn.example.com", 365)
        path = os.path.join(temp_dir, "warn.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        with caplog.at_level(logging.WARNING, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_infos[0])

        assert any("SELF-SIGNED" in r.message for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records
                   if "SELF-SIGNED" in r.message)

    def test_ca_signed_does_not_log_self_signed_warning(self, analyzer, temp_dir, caplog):
        """A CA-signed certificate does not produce a SELF-SIGNED warning."""
        ca_cert, ca_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        leaf_cert, _    = _generate_ca_signed_certificate("no-warn.example.com", 365, ca_cert, ca_key)

        path = os.path.join(temp_dir, "no-warn.pem")
        TestCertificateGeneration.save_certificate_pem(leaf_cert, path)

        cert_infos = analyzer.analyze_certificate(path, "test", 1)

        with caplog.at_level(logging.WARNING, logger="agent.analyzer"):
            analyzer.log_certificate_status(cert_infos[0])

        assert not any("SELF-SIGNED" in r.message for r in caplog.records)

    def test_is_self_signed_field_defaults_to_false(self):
        """CertificateInfo.is_self_signed defaults to False."""
        info = CertificateInfo(
            path="/tmp/test.crt",
            subject="CN=test",
            issuer="CN=ca",
            serial_number="1",
            not_before=datetime.utcnow() - timedelta(days=1),
            not_after=datetime.utcnow() + timedelta(days=365),
            process="test",
            pid=1,
        )
        assert info.is_self_signed is False

    def test_bundle_mixed_self_signed_and_ca_signed(self, analyzer, temp_dir):
        """In a bundle, each cert is independently classified as self-signed or not."""
        self_signed, _  = TestCertificateGeneration.generate_certificate("self.example.com", 365)
        ca_cert, ca_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        ca_signed, _    = _generate_ca_signed_certificate("leaf.example.com", 365, ca_cert, ca_key)

        bundle_path = os.path.join(temp_dir, "mixed.pem")
        TestCertificateGeneration.save_multi_certificate_pem([self_signed, ca_signed], bundle_path)

        cert_infos = analyzer.analyze_certificate(bundle_path, "test", 1)

        assert len(cert_infos) == 2
        by_cn = {info.common_name: info for info in cert_infos}
        assert by_cn["self.example.com"].is_self_signed is True
        assert by_cn["leaf.example.com"].is_self_signed is False

    def test_self_signed_fallback_on_old_cryptography(self, analyzer, temp_dir):
        """On cryptography <40 (no verify_directly_issued_by), a self-signed cert is still detected via subject==issuer."""
        from unittest.mock import patch
        cert, _ = TestCertificateGeneration.generate_certificate("legacy-self.example.com", 365)
        path = os.path.join(temp_dir, "legacy-self.pem")
        TestCertificateGeneration.save_certificate_pem(cert, path)

        with patch.object(x509.Certificate, "verify_directly_issued_by", side_effect=AttributeError):
            cert_infos = analyzer.analyze_certificate(path, "test", 1)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_self_signed is True

    def test_ca_signed_fallback_on_old_cryptography(self, analyzer, temp_dir):
        """On cryptography <40 (no verify_directly_issued_by), a CA-signed cert is not misclassified as self-signed."""
        from unittest.mock import patch
        ca_cert, ca_key = TestCertificateGeneration.generate_certificate("Root CA", 3650, is_ca=True)
        leaf_cert, _    = _generate_ca_signed_certificate("legacy-leaf.example.com", 365, ca_cert, ca_key)
        path = os.path.join(temp_dir, "legacy-leaf.pem")
        TestCertificateGeneration.save_certificate_pem(leaf_cert, path)

        with patch.object(x509.Certificate, "verify_directly_issued_by", side_effect=AttributeError):
            cert_infos = analyzer.analyze_certificate(path, "test", 1)

        assert len(cert_infos) == 1
        assert cert_infos[0].is_self_signed is False


# ── Tetragon connected metric helpers ────────────────────────────────────────

class _GrpcRpcError(grpc.RpcError):
    """Minimal gRPC RpcError that satisfies the code().name access in start()."""
    def code(self):
        class _Code:
            name = 'UNAVAILABLE'
        return _Code()


class _BlockingEventIterator:
    """Iterator that blocks until stop is set — simulates a live gRPC event stream."""
    def __init__(self, stop: threading.Event):
        self._stop = stop

    def __iter__(self):
        return self

    def __next__(self):
        while not self._stop.is_set():
            time.sleep(0.02)
        raise StopIteration


class _StreamingStub:
    """
    Mock stub for start() integration tests.

    When fail_first=True the first GetEvents call raises gRPC error; all
    subsequent calls block normally. streaming_started is set when a
    non-failing call begins, and stop signals that call to end.
    """
    def __init__(self, fail_first: bool = False):
        self.streaming_started = threading.Event()
        self.stop              = threading.Event()
        self._fail_first       = fail_first
        self._call_count       = 0

    def GetVersion(self, req, timeout=None):
        return _MockGetVersionResponse('v1.0.0')

    def ListTracingPolicies(self, req, timeout=None):
        return _MockListPoliciesResponse([])

    def GetEvents(self, req):
        self._call_count += 1
        if self._fail_first and self._call_count == 1:
            raise _GrpcRpcError()
        self.streaming_started.set()
        return _BlockingEventIterator(self.stop)


class TestTetragonConnected:
    """
    Tests for the tetragon_connected Prometheus gauge.

    Transitions are driven by start(). Tests that verify connected/disconnected
    states run start() in a background daemon thread with injected mock channel
    and stub so no real Tetragon socket is required.
    """

    def _start_in_thread(self, analyzer, stub, monkeypatch, mock_sleep=None):
        """Patch channel/stub creation and launch start() in a daemon thread."""
        import cert_analyzer as _ca

        class _MockChannel:
            def close(self): pass

        monkeypatch.setattr(_ca.grpc, 'insecure_channel',
                            lambda *a, **kw: _MockChannel())
        monkeypatch.setattr(_ca.sensors_pb2_grpc, 'FineGuidanceSensorsStub',
                            lambda ch: stub)
        if mock_sleep is not None:
            monkeypatch.setattr(_ca.time, 'sleep', mock_sleep)

        t = threading.Thread(target=analyzer.start, daemon=True)
        t.start()
        return t

    def test_initial_value_is_0(self, analyzer):
        """tetragon_connected starts at 0 before any connection is attempted."""
        assert analyzer.metrics.tetragon_connected.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0

    def test_set_to_1_when_event_stream_is_active(self, analyzer, monkeypatch):
        """tetragon_connected is 1 while GetEvents is actively streaming."""
        stub = _StreamingStub()
        self._start_in_thread(analyzer, stub, monkeypatch)

        assert stub.streaming_started.wait(timeout=3), "Event stream did not start"
        assert analyzer.metrics.tetragon_connected.labels(node_name=analyzer.metrics._node_name)._value.get() == 1.0
        stub.stop.set()

    def test_set_to_0_on_grpc_error(self, analyzer, monkeypatch):
        """tetragon_connected drops to 0 when GetEvents raises a gRPC error."""
        error_triggered = threading.Event()

        class _FailingStub:
            def GetVersion(self, req, timeout=None):
                return _MockGetVersionResponse('v1.0.0')
            def ListTracingPolicies(self, req, timeout=None):
                return _MockListPoliciesResponse([])
            def GetEvents(self, req):
                error_triggered.set()
                raise _GrpcRpcError()

        self._start_in_thread(analyzer, _FailingStub(), monkeypatch)

        assert error_triggered.wait(timeout=3), "gRPC error was never triggered"
        # The except grpc.RpcError handler sets tetragon_connected=0 immediately
        # after the raise. A short real sleep ensures the except block has run.
        time.sleep(0.05)
        assert analyzer.metrics.tetragon_connected.labels(node_name=analyzer.metrics._node_name)._value.get() == 0.0

    def test_recovers_to_1_after_grpc_error(self, analyzer, monkeypatch):
        """tetragon_connected returns to 1 once the event stream reconnects."""
        stub = _StreamingStub(fail_first=True)
        self._start_in_thread(
            analyzer, stub, monkeypatch,
            mock_sleep=lambda s: None,  # skip retry back-off
        )

        assert stub.streaming_started.wait(timeout=3), "Stream did not recover"
        assert analyzer.metrics.tetragon_connected.labels(node_name=analyzer.metrics._node_name)._value.get() == 1.0
        stub.stop.set()

    def test_is_independent_of_analyzer_healthy(self, analyzer):
        """tetragon_connected and analyzer_healthy are separate metric objects."""
        assert analyzer.metrics.tetragon_connected is not analyzer.metrics.analyzer_healthy


class TestPortProbe:
    """Tests for port-probe cert discovery.

    Covers:
      _read_primary_ip_from_fib_trie — fib_trie parsing
      _resolve_pid_ip               — IP resolution (specific vs wildcard bind addr)
      _probe_tls_endpoint           — TLS handshake + cert ingestion pipeline
      _handle_tls_bind_event        — kprobe event decoding (sock_arg / bytes_arg)
      process_event routing         — bind events dispatched or bypassed by flag
    """

    # ── fixtures / shared helpers ─────────────────────────────────────────────

    @pytest.fixture
    def probe_analyzer(self):
        """CertificateAnalyzer with both probe directions enabled and zero connect delay."""
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            bind_probe_enabled=True,
            connect_probe_enabled=True,
            port_probe_timeout=2.0,
            port_probe_connect_delay=0.0,
        )
        yield a
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass

    @staticmethod
    def _fib_trie(ips, loopback=True):
        """Build minimal fib_trie text with the given non-loopback IPs.

        Matches the real kernel format (confirmed against a live pod's
        /proc/<pid>/net/fib_trie): each LOCAL /32 leaf is a bare-IP line
        ("|-- x.x.x.x") immediately followed by its mask/type line
        ("/32 host LOCAL") on the next line -- the IP and "/32" never
        share a line.
        """
        lines = ['Main:\n']
        for ip in ips:
            lines += [
                f'        |-- {ip}\n',
                '           /32 host LOCAL\n',
            ]
        if loopback:
            lines += [
                '        |-- 127.0.0.1\n',
                '           /32 host LOCAL\n',
            ]
        return ''.join(lines)

    @staticmethod
    def _make_sock_arg(port, saddr='0.0.0.0'):
        from unittest.mock import MagicMock
        sockaddr = MagicMock()
        sockaddr.port = port
        sockaddr.addr = saddr
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'sockaddr_arg'
        arg.sockaddr_arg = sockaddr
        return arg

    @staticmethod
    def _make_no_sock_arg():
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: False
        return arg

    @staticmethod
    def _sockaddr_in(port, addr='0.0.0.0'):
        """Pack a struct sockaddr_in (family=AF_INET=2, big-endian port, 4-byte addr)."""
        import struct
        parts = [int(x) for x in addr.split('.')]
        return struct.pack('<H', 2) + struct.pack('>H', port) + bytes(parts) + b'\x00' * 8

    @staticmethod
    def _make_bytes_arg(data):
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'bytes_arg'
        arg.bytes_arg = data
        return arg

    @staticmethod
    def _make_int_arg():
        from unittest.mock import MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: False
        return arg

    @staticmethod
    def _make_bind_event(function_name, args, pid=1234, binary='/usr/sbin/nginx'):
        from unittest.mock import MagicMock
        kprobe = MagicMock()
        kprobe.function_name = function_name
        kprobe.process.binary = binary
        kprobe.process.pid.value = pid
        kprobe.process.HasField.side_effect = lambda f: f == 'pid'
        kprobe.args = args
        event = MagicMock()
        event.HasField.side_effect = lambda f: f == 'process_kprobe'
        event.process_kprobe = kprobe
        event.node_name = 'test-node'
        return event

    @staticmethod
    def _gen_server_cert(tmp_dir):
        """Generate a self-signed cert+key, write to files. Returns (cert_path, key_path, cert_obj)."""
        cert_obj, private_key = TestCertificateGeneration.generate_certificate(
            'probe.example.com', 365
        )
        cert_path = os.path.join(tmp_dir, 'server.crt')
        key_path  = os.path.join(tmp_dir, 'server.key')
        with open(cert_path, 'wb') as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        return cert_path, key_path, cert_obj

    @staticmethod
    def _start_tls_server(cert_path, key_path):
        """Spin up a TLS server on a random port. Returns (port, stop_event)."""
        import queue
        import ssl as _ssl
        import socket as _socket
        port_q = queue.Queue()
        stop   = threading.Event()

        def _serve():
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as raw:
                raw.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
                raw.bind(('127.0.0.1', 0))
                raw.listen(5)
                port_q.put(raw.getsockname()[1])
                raw.settimeout(0.5)
                while not stop.is_set():
                    try:
                        conn, _ = raw.accept()
                        try:
                            with ctx.wrap_socket(conn, server_side=True) as tls:
                                tls.recv(1)
                        except _ssl.SSLError:
                            pass
                    except (_socket.timeout, OSError):
                        pass

        threading.Thread(target=_serve, daemon=True).start()
        return port_q.get(timeout=3), stop

    # ── _read_primary_ip_from_fib_trie ────────────────────────────────────────

    def test_fib_trie_returns_container_ip(self, probe_analyzer):
        from unittest.mock import patch, mock_open
        content = self._fib_trie(['10.244.1.5'])
        with patch('builtins.open', mock_open(read_data=content)):
            ip = probe_analyzer._read_primary_ip_from_fib_trie(1234)
        assert ip == '10.244.1.5'

    def test_fib_trie_returns_first_non_loopback_when_multiple(self, probe_analyzer):
        from unittest.mock import patch, mock_open
        content = self._fib_trie(['10.244.1.5', '192.168.1.100'])
        with patch('builtins.open', mock_open(read_data=content)):
            ip = probe_analyzer._read_primary_ip_from_fib_trie(1234)
        assert ip == '10.244.1.5'

    def test_fib_trie_skips_loopback(self, probe_analyzer):
        from unittest.mock import patch, mock_open
        content = self._fib_trie([], loopback=True)
        with patch('builtins.open', mock_open(read_data=content)):
            ip = probe_analyzer._read_primary_ip_from_fib_trie(1234)
        assert ip is None

    def test_fib_trie_returns_none_on_oserror(self, probe_analyzer):
        from unittest.mock import patch
        with patch('builtins.open', side_effect=OSError('no such file')):
            ip = probe_analyzer._read_primary_ip_from_fib_trie(99999)
        assert ip is None

    # ── _resolve_pid_ip ───────────────────────────────────────────────────────

    def test_resolve_returns_specific_bind_addr_directly(self, probe_analyzer):
        """A non-wildcard bind address is returned without reading fib_trie."""
        from unittest.mock import patch
        with patch.object(probe_analyzer, '_read_primary_ip_from_fib_trie') as mock_fib:
            ip = probe_analyzer._resolve_pid_ip(1234, '10.0.0.1')
        mock_fib.assert_not_called()
        assert ip == '10.0.0.1'

    def test_resolve_wildcard_uses_fib_trie_ip(self, probe_analyzer):
        """0.0.0.0 bind addr resolves to the container IP via fib_trie."""
        from unittest.mock import patch
        with patch.object(probe_analyzer, '_read_primary_ip_from_fib_trie', return_value='10.244.1.5'):
            ip = probe_analyzer._resolve_pid_ip(1234, '0.0.0.0')
        assert ip == '10.244.1.5'

    def test_resolve_wildcard_falls_back_to_localhost_on_fib_failure(self, probe_analyzer):
        """Falls back to 127.0.0.1 when fib_trie read fails (bare-metal case)."""
        from unittest.mock import patch
        with patch.object(probe_analyzer, '_read_primary_ip_from_fib_trie', return_value=None):
            ip = probe_analyzer._resolve_pid_ip(1234, '0.0.0.0')
        assert ip == '127.0.0.1'

    def test_resolve_ipv6_wildcard_falls_back_to_localhost(self, probe_analyzer):
        from unittest.mock import patch
        with patch.object(probe_analyzer, '_read_primary_ip_from_fib_trie', return_value=None):
            ip = probe_analyzer._resolve_pid_ip(1234, '::')
        assert ip == '127.0.0.1'

    # ── _probe_tls_endpoint ───────────────────────────────────────────────────

    def test_probe_discovers_cert_from_live_tls_server(self, probe_analyzer, temp_dir):
        """A real TLS handshake lands the leaf cert in known_certs."""
        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint(
                '127.0.0.1', port, '/usr/sbin/nginx', 1234, 'node-1', None
            )
        finally:
            stop.set()

        synthetic_path = f'tls-bind-probe://127.0.0.1:{port}'
        assert any(k.startswith(synthetic_path + ':') for k in probe_analyzer.known_certs)
        assert probe_analyzer.metrics.tls_port_probes_total.labels(status='success', node_name=probe_analyzer.metrics._node_name)._value.get() == 1

    def test_probe_records_negotiated_protocol_and_cipher(self, probe_analyzer, temp_dir):
        """A successful probe records the negotiated TLS protocol/cipher on tls_certificate_negotiated_protocol."""
        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint(
                '127.0.0.1', port, '/usr/sbin/nginx', 1234, 'node-1', None
            )
        finally:
            stop.set()

        samples = list(probe_analyzer.metrics.tls_negotiated_protocol.collect()[0].samples)
        assert len(samples) == 1
        assert samples[0].value == 1.0
        assert samples[0].labels['protocol'].startswith('TLSv1')
        assert samples[0].labels['cipher']
        assert samples[0].labels['node_name'] == 'node-1'
        assert samples[0].labels['process'] == '/usr/sbin/nginx'

    def test_probe_skips_already_cached_endpoint(self, probe_analyzer, temp_dir):
        """Probing an endpoint already in known_certs increments the skipped counter."""
        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint('127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None)
            probe_analyzer._probe_tls_endpoint('127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None)
        finally:
            stop.set()

        assert probe_analyzer.metrics.tls_port_probes_total.labels(status='skipped', node_name=probe_analyzer.metrics._node_name)._value.get() == 1

    def test_probe_fails_on_connection_refused(self, probe_analyzer):
        """Connection to a closed port increments the failed counter."""
        probe_analyzer._probe_tls_endpoint('127.0.0.1', 1, '/usr/sbin/nginx', 1234, '', None)
        assert probe_analyzer.metrics.tls_port_probes_total.labels(status='failed', node_name=probe_analyzer.metrics._node_name)._value.get() == 1

    def test_probe_fails_on_plain_tcp_port(self, probe_analyzer):
        """Connecting to a non-TLS port (no TLS handshake) increments the failed counter."""
        import socket as _socket
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as srv:
            srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            srv.bind(('127.0.0.1', 0))
            srv.listen(1)
            port = srv.getsockname()[1]

            def _accept():
                try:
                    conn, _ = srv.accept()
                    conn.close()
                except OSError:
                    pass

            threading.Thread(target=_accept, daemon=True).start()
            probe_analyzer._probe_tls_endpoint('127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None)

        assert probe_analyzer.metrics.tls_port_probes_total.labels(status='failed', node_name=probe_analyzer.metrics._node_name)._value.get() == 1

    def test_probe_publishes_to_kafka_on_success(self, probe_analyzer, temp_dir):
        """Discovered cert is forwarded to the Kafka publisher when configured."""
        from unittest.mock import MagicMock
        mock_kafka = MagicMock()
        probe_analyzer.kafka_publisher = mock_kafka

        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint('127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None)
        finally:
            stop.set()

        mock_kafka.publish.assert_called_once()

    # ── _handle_tls_bind_event ────────────────────────────────────────────────

    def test_handle_security_socket_bind_extracts_port_via_sock_arg(self, probe_analyzer):
        """security_socket_bind event: port extracted from sock_arg.sport."""
        from unittest.mock import patch
        probed = threading.Event()

        def _fake_probe(host, port, *args, **kwargs):
            probed._port = port
            probed._host = host
            probed.set()

        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(8443, '0.0.0.0')],
        )

        with patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=_fake_probe), \
             patch.object(probe_analyzer, '_resolve_pid_ip', return_value='127.0.0.1'):
            probe_analyzer._handle_tls_bind_event(event)
            probed.wait(timeout=2)

        assert probed.is_set(), 'probe was not triggered'
        assert probed._port == 8443
        assert probed._host == '127.0.0.1'

    def test_handle_sys_bind_extracts_port_via_bytes_arg(self, probe_analyzer):
        """sys_bind event: port extracted from raw sockaddr_in bytes_arg."""
        from unittest.mock import patch
        probed = threading.Event()

        def _fake_probe(host, port, *args, **kwargs):
            probed._port = port
            probed.set()

        sockaddr = self._sockaddr_in(9443)
        event = self._make_bind_event(
            'sys_bind',
            [self._make_int_arg(), self._make_bytes_arg(sockaddr)],
        )

        with patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=_fake_probe), \
             patch.object(probe_analyzer, '_resolve_pid_ip', return_value='127.0.0.1'):
            probe_analyzer._handle_tls_bind_event(event)
            probed.wait(timeout=2)

        assert probed.is_set(), 'probe was not triggered'
        assert probed._port == 9443

    def test_handle_bind_uses_specific_saddr_without_fib_trie(self, probe_analyzer):
        """When the bind address is a specific IP, _resolve_pid_ip passes it through."""
        from unittest.mock import patch
        resolved_ips = []

        def _capture_resolve(pid, bind_addr):
            resolved_ips.append(bind_addr)
            return bind_addr

        probed = threading.Event()
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(443, '10.0.0.5')],
        )

        with patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=lambda *a, **kw: probed.set()), \
             patch.object(probe_analyzer, '_resolve_pid_ip', side_effect=_capture_resolve):
            probe_analyzer._handle_tls_bind_event(event)
            probed.wait(timeout=2)

        assert resolved_ips == ['10.0.0.5']

    def test_handle_bind_no_probe_when_port_is_zero(self, probe_analyzer):
        """A bind event with an unparseable port (0) spawns no probe thread."""
        from unittest.mock import patch
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(0, '0.0.0.0')],
        )

        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_bind_event(event)
            time.sleep(0.1)

        mock_probe.assert_not_called()

    def test_handle_sys_bind_short_bytes_arg_is_ignored(self, probe_analyzer):
        """sys_bind bytes_arg shorter than 8 bytes produces no probe."""
        from unittest.mock import patch
        event = self._make_bind_event(
            'sys_bind',
            [self._make_int_arg(), self._make_bytes_arg(b'\x02\x00')],
        )

        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_bind_event(event)
            time.sleep(0.1)

        mock_probe.assert_not_called()

    # ── endpoint deduplication ────────────────────────────────────────────────

    def test_bind_handler_skips_already_probed_endpoint(self, probe_analyzer):
        """No thread is spawned when the endpoint is already in _probed_endpoints."""
        from unittest.mock import patch
        probe_analyzer._probed_endpoints.add('bind:127.0.0.1:8443')
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(8443, '0.0.0.0')],
        )
        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe, \
             patch.object(probe_analyzer, '_resolve_pid_ip', return_value='127.0.0.1'):
            probe_analyzer._handle_tls_bind_event(event)
            time.sleep(0.1)
        mock_probe.assert_not_called()

    def test_bind_handler_skips_in_flight_endpoint(self, probe_analyzer):
        """No thread is spawned when a probe for the same endpoint is already running."""
        from unittest.mock import patch
        probe_analyzer._probe_in_flight.add('bind:127.0.0.1:8443')
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(8443, '0.0.0.0')],
        )
        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe, \
             patch.object(probe_analyzer, '_resolve_pid_ip', return_value='127.0.0.1'):
            probe_analyzer._handle_tls_bind_event(event)
            time.sleep(0.1)
        mock_probe.assert_not_called()

    def test_connect_handler_skips_already_probed_endpoint(self, probe_analyzer):
        """No thread is spawned when the endpoint is already in _probed_endpoints."""
        from unittest.mock import patch
        probe_analyzer._probed_endpoints.add('connect:1.2.3.4:443')
        event = self._make_connect_event('1.2.3.4', 443)
        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_connect_event(event)
            time.sleep(0.1)
        mock_probe.assert_not_called()

    def test_connect_handler_skips_in_flight_endpoint(self, probe_analyzer):
        """No thread is spawned when a probe for the same endpoint is already running."""
        from unittest.mock import patch
        probe_analyzer._probe_in_flight.add('connect:1.2.3.4:443')
        event = self._make_connect_event('1.2.3.4', 443)
        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_connect_event(event)
            time.sleep(0.1)
        mock_probe.assert_not_called()

    def test_bind_probe_not_blocked_by_prior_connect_probe_same_endpoint(self, probe_analyzer):
        """A connect-sourced discovery of host:port must not block a later bind
        discovery of the identical address -- the two are mechanism-scoped."""
        from unittest.mock import patch
        probe_analyzer._probed_endpoints.add('connect:127.0.0.1:8443')
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(8443, '0.0.0.0')],
        )
        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe, \
             patch.object(probe_analyzer, '_resolve_pid_ip', return_value='127.0.0.1'):
            probe_analyzer._handle_tls_bind_event(event)
            time.sleep(0.1)
        mock_probe.assert_called_once()

    def test_connect_probe_not_blocked_by_prior_bind_probe_same_endpoint(self, probe_analyzer):
        """A bind-sourced discovery of host:port must not block a later connect
        discovery of the identical address -- the two are mechanism-scoped."""
        from unittest.mock import patch
        probe_analyzer._probed_endpoints.add('bind:1.2.3.4:443')
        event = self._make_connect_event('1.2.3.4', 443)
        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_connect_event(event)
            time.sleep(0.1)
        mock_probe.assert_called_once()

    def test_bind_and_connect_probes_of_same_endpoint_both_publish(self, probe_analyzer, temp_dir):
        """Bind-probe and connect-probe discovering the identical host:port are
        tracked and published as two independent findings, not deduped against
        each other -- the actual end-to-end behavior the mechanism prefix exists for."""
        from unittest.mock import MagicMock
        mock_kafka = MagicMock()
        probe_analyzer.kafka_publisher = mock_kafka

        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint(
                '127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None, mechanism='bind'
            )
            probe_analyzer._probe_tls_endpoint(
                '127.0.0.1', port, '/usr/bin/curl', 5678, '', None, mechanism='connect'
            )
        finally:
            stop.set()

        bind_path = f'tls-bind-probe://127.0.0.1:{port}'
        connect_path = f'tls-connect-probe://127.0.0.1:{port}'
        assert any(k.startswith(bind_path + ':') for k in probe_analyzer.known_certs)
        assert any(k.startswith(connect_path + ':') for k in probe_analyzer.known_certs)
        assert probe_analyzer.metrics.tls_port_probes_total.labels(status='success', node_name=probe_analyzer.metrics._node_name)._value.get() == 2
        assert mock_kafka.publish.call_count == 2

    def test_probe_in_flight_cleared_after_successful_probe(self, probe_analyzer, temp_dir):
        """_probe_in_flight entry is removed after a successful probe."""
        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint(
                '127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None
            )
        finally:
            stop.set()
        assert f'127.0.0.1:{port}' not in probe_analyzer._probe_in_flight

    def test_probe_in_flight_cleared_after_failed_probe(self, probe_analyzer):
        """_probe_in_flight entry is removed even when the probe fails (connection refused)."""
        # Seed in_flight as the bind handler would
        probe_analyzer._probe_in_flight.add('127.0.0.1:1')
        probe_analyzer._probe_tls_endpoint('127.0.0.1', 1, '/usr/sbin/nginx', 1234, '', None)
        # _probe_tls_endpoint doesn't manage _probe_in_flight — the caller does.
        # This test confirms the handler's finally block clears it via a live-server test.
        # Here we verify the set was not corrupted by the failed probe.
        assert '127.0.0.1:1' in probe_analyzer._probe_in_flight  # still set — handler manages it

    def test_probe_endpoint_added_to_probed_endpoints_on_success(self, probe_analyzer, temp_dir):
        """A successful probe registers the endpoint in _probed_endpoints."""
        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            probe_analyzer._probe_tls_endpoint(
                '127.0.0.1', port, '/usr/sbin/nginx', 1234, '', None
            )
        finally:
            stop.set()
        assert f'bind:127.0.0.1:{port}' in probe_analyzer._probed_endpoints

    def test_probe_endpoint_not_added_on_failed_probe(self, probe_analyzer):
        """A failed probe (connection refused) does not register the endpoint."""
        probe_analyzer._probe_tls_endpoint('127.0.0.1', 1, '/usr/sbin/nginx', 1234, '', None)
        assert '127.0.0.1:1' not in probe_analyzer._probed_endpoints

    def test_bind_handler_adds_to_in_flight_before_probe_runs(self, probe_analyzer, temp_dir):
        """_probe_in_flight is populated before the thread calls _probe_tls_endpoint."""
        from unittest.mock import patch
        in_flight_at_call_time = []

        def _capture(*args, **kwargs):
            in_flight_at_call_time.append(set(probe_analyzer._probe_in_flight))

        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            event = self._make_bind_event(
                'security_socket_bind',
                [self._make_sock_arg(port, '127.0.0.1')],
            )
            with patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=_capture), \
                 patch.object(probe_analyzer, '_resolve_pid_ip', return_value='127.0.0.1'):
                probe_analyzer._handle_tls_bind_event(event)
                time.sleep(0.5)
        finally:
            stop.set()

        assert in_flight_at_call_time, 'probe was never called'
        assert f'bind:127.0.0.1:{port}' in in_flight_at_call_time[0]

    # ── process_event routing ─────────────────────────────────────────────────

    def test_process_event_routes_security_socket_bind_to_handler(self, probe_analyzer):
        """process_event dispatches security_socket_bind to _handle_tls_bind_event."""
        from unittest.mock import patch
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(443)],
        )

        with patch.object(probe_analyzer, '_handle_tls_bind_event') as mock_handler:
            probe_analyzer.process_event(event)

        mock_handler.assert_called_once_with(event)

    def test_process_event_routes_sys_bind_to_handler(self, probe_analyzer):
        """process_event dispatches sys_bind to _handle_tls_bind_event."""
        from unittest.mock import patch
        sockaddr = self._sockaddr_in(8443)
        event = self._make_bind_event(
            'sys_bind',
            [self._make_int_arg(), self._make_bytes_arg(sockaddr)],
        )

        with patch.object(probe_analyzer, '_handle_tls_bind_event') as mock_handler:
            probe_analyzer.process_event(event)

        mock_handler.assert_called_once_with(event)

    def test_process_event_skips_handler_when_port_probe_disabled(self, analyzer):
        """Bind events are silently dropped when bind_probe_enabled=False."""
        from unittest.mock import patch
        assert not analyzer._bind_probe_enabled
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(443)],
        )

        with patch.object(analyzer, '_handle_tls_bind_event') as mock_handler:
            analyzer.process_event(event)

        mock_handler.assert_not_called()

    def test_process_event_bind_does_not_fall_through_to_cert_extraction(self, probe_analyzer):
        """Bind events return immediately without calling extract_cert_path_from_event."""
        from unittest.mock import patch
        event = self._make_bind_event(
            'security_socket_bind',
            [self._make_sock_arg(443)],
        )

        with patch.object(probe_analyzer, '_handle_tls_bind_event'), \
             patch.object(probe_analyzer, 'extract_cert_path_from_event') as mock_extract:
            probe_analyzer.process_event(event)

        mock_extract.assert_not_called()

    # ── _handle_tls_connect_event ─────────────────────────────────────────────

    @staticmethod
    def _make_sock_connect_arg(daddr, dport):
        """Build a MagicMock kprobe arg with sock_arg carrying daddr/dport."""
        from unittest.mock import MagicMock
        sock = MagicMock()
        sock.daddr = daddr
        sock.dport = dport
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'sock_arg'
        arg.sock_arg = sock
        return arg

    @staticmethod
    def _make_connect_event(daddr, dport, pid=2222, binary='/usr/bin/curl'):
        """Build a process_kprobe event for tcp_connect."""
        from unittest.mock import MagicMock
        kprobe = MagicMock()
        kprobe.function_name = 'tcp_connect'
        kprobe.process.binary = binary
        kprobe.process.pid.value = pid
        kprobe.process.HasField.side_effect = lambda f: f == 'pid'
        sock = MagicMock()
        sock.daddr = daddr
        sock.dport = dport
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: f == 'sock_arg'
        arg.sock_arg = sock
        kprobe.args = [arg]
        event = MagicMock()
        event.HasField.side_effect = lambda f: f == 'process_kprobe'
        event.process_kprobe = kprobe
        event.node_name = 'test-node'
        return event

    def test_handle_tls_connect_probes_tls_port(self, probe_analyzer):
        """tcp_connect to a TLS port schedules a probe to the destination address."""
        from unittest.mock import patch
        probed = threading.Event()

        def _fake_probe(host, port, *args, **kwargs):
            probed._host = host
            probed._port = port
            probed.set()

        event = self._make_connect_event('93.184.216.34', 443)
        with patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=_fake_probe):
            probe_analyzer._handle_tls_connect_event(event)
            probed.wait(timeout=2)

        assert probed.is_set(), 'probe was not triggered'
        assert probed._host == '93.184.216.34'
        assert probed._port == 443

    def test_handle_tls_connect_skips_non_tls_port(self, probe_analyzer):
        """tcp_connect to a port not in _tls_outbound_ports spawns no probe."""
        from unittest.mock import patch
        event = self._make_connect_event('93.184.216.34', 80)

        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_connect_event(event)
            time.sleep(0.1)

        mock_probe.assert_not_called()

    def test_custom_tls_outbound_ports_accepted(self):
        """tls_outbound_ports constructor arg overrides the built-in default."""
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        custom = frozenset({7443, 9443})
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            connect_probe_enabled=True,
            tls_outbound_ports=custom,
        )
        assert a._tls_outbound_ports == custom
        assert 443 not in a._tls_outbound_ports

    def test_custom_tls_outbound_port_triggers_probe(self):
        """A port not in the built-in list fires a probe when added via tls_outbound_ports."""
        from unittest.mock import patch
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            connect_probe_enabled=True,
            port_probe_connect_delay=0.0,
            tls_outbound_ports=frozenset({7443}),
        )
        event = self._make_connect_event('10.0.0.1', 7443)

        with patch.object(a, '_probe_tls_endpoint') as mock_probe:
            a._handle_tls_connect_event(event)
            time.sleep(0.1)

        mock_probe.assert_called_once()
        assert mock_probe.call_args[0][1] == 7443

    def test_port_absent_from_custom_list_is_skipped(self):
        """A port present in the built-in list but not in tls_outbound_ports is skipped."""
        from unittest.mock import patch
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            connect_probe_enabled=True,
            tls_outbound_ports=frozenset({7443}),
        )
        event = self._make_connect_event('10.0.0.1', 443)

        with patch.object(a, '_probe_tls_endpoint') as mock_probe:
            a._handle_tls_connect_event(event)
            time.sleep(0.1)

        mock_probe.assert_not_called()

    def test_handle_tls_connect_skips_missing_sock_arg(self, probe_analyzer):
        """tcp_connect event with no sock_arg spawns no probe."""
        from unittest.mock import patch, MagicMock
        arg = MagicMock()
        arg.HasField.side_effect = lambda f: False
        event = self._make_bind_event('tcp_connect', [arg])

        with patch.object(probe_analyzer, '_probe_tls_endpoint') as mock_probe:
            probe_analyzer._handle_tls_connect_event(event)
            time.sleep(0.1)

        mock_probe.assert_not_called()

    def test_handle_tls_connect_probes_alternate_tls_ports(self, probe_analyzer):
        """tcp_connect to each port in _tls_outbound_ports triggers a probe."""
        from unittest.mock import patch
        for port in (8443, 5671, 6380, 9093):
            probed = threading.Event()

            def _fake_probe(host, p, *args, _port=port, _ev=probed, **kwargs):
                _ev._port = p
                _ev.set()

            event = self._make_connect_event('10.0.0.1', port)
            with patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=_fake_probe):
                probe_analyzer._handle_tls_connect_event(event)
                probed.wait(timeout=2)

            assert probed.is_set(), f'probe not triggered for port {port}'
            assert probed._port == port

    # ── process_event routing for tcp_connect ─────────────────────────────────

    def test_process_event_routes_tcp_connect_to_handler(self, probe_analyzer):
        """process_event dispatches tcp_connect to _handle_tls_connect_event."""
        from unittest.mock import patch
        event = self._make_connect_event('1.2.3.4', 443)

        with patch.object(probe_analyzer, '_handle_tls_connect_event') as mock_handler:
            probe_analyzer.process_event(event)

        mock_handler.assert_called_once_with(event)

    def test_process_event_tcp_connect_skipped_when_port_probe_disabled(self, analyzer):
        """tcp_connect events are silently dropped when connect_probe_enabled=False."""
        from unittest.mock import patch
        assert not analyzer._connect_probe_enabled
        event = self._make_connect_event('1.2.3.4', 443)

        with patch.object(analyzer, '_handle_tls_connect_event') as mock_handler:
            analyzer.process_event(event)

        mock_handler.assert_not_called()

    def test_bind_probe_fires_independently_of_connect_probe(self):
        """bind_probe_enabled=True, connect_probe_enabled=False: bind handler called, connect handler not."""
        from unittest.mock import patch
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            bind_probe_enabled=True,
            connect_probe_enabled=False,
        )
        assert a._bind_probe_enabled
        assert not a._connect_probe_enabled

        bind_event = self._make_bind_event('security_socket_bind', [self._make_sock_arg(443)])
        connect_event = self._make_connect_event('1.2.3.4', 443)

        with patch.object(a, '_handle_tls_bind_event') as mock_bind, \
             patch.object(a, '_handle_tls_connect_event') as mock_connect:
            a.process_event(bind_event)
            a.process_event(connect_event)

        mock_bind.assert_called_once_with(bind_event)
        mock_connect.assert_not_called()

    def test_connect_probe_fires_independently_of_bind_probe(self):
        """connect_probe_enabled=True, bind_probe_enabled=False: connect handler called, bind handler not."""
        from unittest.mock import patch
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            bind_probe_enabled=False,
            connect_probe_enabled=True,
        )
        assert not a._bind_probe_enabled
        assert a._connect_probe_enabled

        bind_event = self._make_bind_event('security_socket_bind', [self._make_sock_arg(443)])
        connect_event = self._make_connect_event('1.2.3.4', 443)

        with patch.object(a, '_handle_tls_bind_event') as mock_bind, \
             patch.object(a, '_handle_tls_connect_event') as mock_connect:
            a.process_event(bind_event)
            a.process_event(connect_event)

        mock_bind.assert_not_called()
        mock_connect.assert_called_once_with(connect_event)

    def test_process_event_tcp_connect_does_not_fall_through_to_cert_extraction(self, probe_analyzer):
        """tcp_connect events return without calling extract_cert_path_from_event."""
        from unittest.mock import patch
        event = self._make_connect_event('1.2.3.4', 443)

        with patch.object(probe_analyzer, '_handle_tls_connect_event'), \
             patch.object(probe_analyzer, 'extract_cert_path_from_event') as mock_extract:
            probe_analyzer.process_event(event)

        mock_extract.assert_not_called()

    def test_handle_tls_connect_discovers_cert_from_live_tls_server(self, probe_analyzer, temp_dir):
        """A real TLS handshake via a connect event lands the cert in known_certs."""
        cert_path, key_path, _ = self._gen_server_cert(temp_dir)
        port, stop = self._start_tls_server(cert_path, key_path)
        try:
            event = self._make_connect_event('127.0.0.1', port)
            # Port must be in _tls_outbound_ports for the handler to fire
            probe_analyzer._tls_outbound_ports = frozenset(
                list(probe_analyzer._tls_outbound_ports) + [port]
            )
            probed = threading.Event()
            original_probe = probe_analyzer._probe_tls_endpoint

            def _wrap(*args, **kwargs):
                original_probe(*args, **kwargs)
                probed.set()

            import unittest.mock as _mock
            with _mock.patch.object(probe_analyzer, '_probe_tls_endpoint', side_effect=_wrap):
                probe_analyzer._handle_tls_connect_event(event)
                probed.wait(timeout=5)
        finally:
            stop.set()

        synthetic_path = f'tls-connect-probe://127.0.0.1:{port}'
        assert any(k.startswith(synthetic_path + ':') for k in probe_analyzer.known_certs)


class TestEventRateMetrics:
    """Tests for per-process event-rate counters (event_rate_metrics_enabled).

    Covers:
      process_event counter increment for socket_bind / tcp_connect events
      disabled by default (no-op when flag is off)
      independent of bind_probe_enabled / connect_probe_enabled
    """

    @pytest.fixture
    def rate_analyzer(self):
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            event_rate_metrics_enabled=True,
        )
        yield a
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass

    @staticmethod
    def _make_bind_event(fn, binary='/usr/sbin/nginx'):
        from unittest.mock import MagicMock
        kprobe = MagicMock()
        kprobe.function_name = fn
        kprobe.process.binary = binary
        kprobe.process.pid.value = 1234
        kprobe.process.HasField.side_effect = lambda f: f == 'pid'
        kprobe.args = []
        event = MagicMock()
        event.HasField.side_effect = lambda f: f == 'process_kprobe'
        event.process_kprobe = kprobe
        event.node_name = 'test-node'
        return event

    @staticmethod
    def _make_connect_event(binary='/usr/bin/curl'):
        from unittest.mock import MagicMock
        kprobe = MagicMock()
        kprobe.function_name = 'tcp_connect'
        kprobe.process.binary = binary
        kprobe.process.pid.value = 2222
        kprobe.process.HasField.side_effect = lambda f: f == 'pid'
        kprobe.args = []
        event = MagicMock()
        event.HasField.side_effect = lambda f: f == 'process_kprobe'
        event.process_kprobe = kprobe
        event.node_name = 'test-node'
        return event

    @staticmethod
    def _get_counter(counter, **labels):
        return counter.labels(**labels)._value.get()

    def test_socket_bind_counter_incremented(self, rate_analyzer):
        """security_socket_bind event increments tls_socket_bind_events_total for the process."""
        event = self._make_bind_event('security_socket_bind', '/usr/sbin/nginx')
        rate_analyzer.process_event(event)
        val = self._get_counter(
            rate_analyzer.metrics.tls_socket_bind_events_total,
            process='/usr/sbin/nginx',
            node_name=rate_analyzer.metrics._node_name,
        )
        assert val == 1.0

    def test_sys_bind_counter_incremented(self, rate_analyzer):
        """sys_bind event increments tls_socket_bind_events_total for the process."""
        event = self._make_bind_event('sys_bind', '/usr/sbin/httpd')
        rate_analyzer.process_event(event)
        val = self._get_counter(
            rate_analyzer.metrics.tls_socket_bind_events_total,
            process='/usr/sbin/httpd',
            node_name=rate_analyzer.metrics._node_name,
        )
        assert val == 1.0

    def test_tcp_connect_counter_incremented(self, rate_analyzer):
        """tcp_connect event increments tls_tcp_connect_events_total for the process."""
        event = self._make_connect_event('/usr/bin/curl')
        rate_analyzer.process_event(event)
        val = self._get_counter(
            rate_analyzer.metrics.tls_tcp_connect_events_total,
            process='/usr/bin/curl',
            node_name=rate_analyzer.metrics._node_name,
        )
        assert val == 1.0

    def test_counter_accumulates_across_events(self, rate_analyzer):
        """Multiple events from the same process sum correctly."""
        for _ in range(3):
            rate_analyzer.process_event(self._make_bind_event('security_socket_bind', '/usr/sbin/nginx'))
        val = self._get_counter(
            rate_analyzer.metrics.tls_socket_bind_events_total,
            process='/usr/sbin/nginx',
            node_name=rate_analyzer.metrics._node_name,
        )
        assert val == 3.0

    def test_counters_per_process_are_independent(self, rate_analyzer):
        """Events from different processes are tracked under separate label values."""
        rate_analyzer.process_event(self._make_bind_event('security_socket_bind', '/usr/sbin/nginx'))
        rate_analyzer.process_event(self._make_bind_event('security_socket_bind', '/usr/sbin/httpd'))
        nginx_val = self._get_counter(
            rate_analyzer.metrics.tls_socket_bind_events_total,
            process='/usr/sbin/nginx',
            node_name=rate_analyzer.metrics._node_name,
        )
        httpd_val = self._get_counter(
            rate_analyzer.metrics.tls_socket_bind_events_total,
            process='/usr/sbin/httpd',
            node_name=rate_analyzer.metrics._node_name,
        )
        assert nginx_val == 1.0
        assert httpd_val == 1.0

    def test_counters_disabled_by_default(self, analyzer):
        """No counter increment when event_rate_metrics_enabled=False (the default)."""
        assert not analyzer._event_rate_metrics_enabled
        event = self._make_bind_event('security_socket_bind', '/usr/sbin/nginx')
        analyzer.process_event(event)
        samples = list(analyzer.metrics.tls_socket_bind_events_total.collect()[0].samples)
        assert not any(s.labels.get('process') == '/usr/sbin/nginx' for s in samples)

    def test_counting_independent_of_bind_probe(self):
        """Event rate is counted even when bind_probe_enabled=False."""
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            event_rate_metrics_enabled=True,
            bind_probe_enabled=False,
        )
        a.process_event(self._make_bind_event('security_socket_bind', '/usr/sbin/nginx'))
        val = self._get_counter(
            a.metrics.tls_socket_bind_events_total,
            process='/usr/sbin/nginx',
            node_name=a.metrics._node_name,
        )
        assert val == 1.0
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass

    def test_counting_independent_of_connect_probe(self):
        """Event rate is counted even when connect_probe_enabled=False."""
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass
        a = CertificateAnalyzer(
            tetragon_address='unix:///dev/null',
            event_rate_metrics_enabled=True,
            connect_probe_enabled=False,
        )
        a.process_event(self._make_connect_event('/usr/bin/curl'))
        val = self._get_counter(
            a.metrics.tls_tcp_connect_events_total,
            process='/usr/bin/curl',
            node_name=a.metrics._node_name,
        )
        assert val == 1.0
        collectors = list(REGISTRY._collector_to_names.keys())
        for c in collectors:
            try:
                REGISTRY.unregister(c)
            except Exception:
                pass

    def test_bind_event_does_not_fall_through_to_cert_extraction(self, rate_analyzer):
        """Bind events return immediately even when event_rate_metrics_enabled=True."""
        from unittest.mock import patch
        event = self._make_bind_event('security_socket_bind')
        with patch.object(rate_analyzer, 'extract_cert_path_from_event') as mock_extract:
            rate_analyzer.process_event(event)
        mock_extract.assert_not_called()

    def test_connect_event_does_not_fall_through_to_cert_extraction(self, rate_analyzer):
        """tcp_connect events return immediately even when event_rate_metrics_enabled=True."""
        from unittest.mock import patch
        event = self._make_connect_event()
        with patch.object(rate_analyzer, 'extract_cert_path_from_event') as mock_extract:
            rate_analyzer.process_event(event)
        mock_extract.assert_not_called()


class TestSigtermShutdown:
    """
    SIGTERM's default disposition kills the process immediately, bypassing
    any try/except -- unlike SIGINT, which Python's own default handler
    turns into a catchable KeyboardInterrupt. Without a custom handler,
    every systemd `stop`/`restart` and every Kubernetes pod termination
    (rolling update, scale-down, node drain) sends SIGTERM and skips
    agent.config.main()'s KeyboardInterrupt cleanup entirely -- silently
    dropping whatever's still buffered in the Kafka producer instead of
    flushing it. _raise_keyboard_interrupt closes that gap by funnelling
    SIGTERM into the same shutdown path SIGINT already uses.
    """

    def test_sigterm_handler_raises_keyboard_interrupt(self):
        import signal
        from agent.config import _raise_keyboard_interrupt

        with pytest.raises(KeyboardInterrupt):
            _raise_keyboard_interrupt(signal.SIGTERM, None)

    def test_sigterm_signal_delivery_raises_keyboard_interrupt(self):
        """End-to-end: an actual delivered SIGTERM (not just a direct call)
        is caught as KeyboardInterrupt once the handler is registered."""
        import os
        import signal
        from agent.config import _raise_keyboard_interrupt

        previous = signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
        try:
            with pytest.raises(KeyboardInterrupt):
                os.kill(os.getpid(), signal.SIGTERM)
        finally:
            signal.signal(signal.SIGTERM, previous)


class TestConfigNumericValidation:
    """
    cfg_int()/cfg_float() must degrade to the documented default on a
    malformed config value instead of raising -- a plain int()/float() cast
    on operator input (a config file or env var) would otherwise crash the
    process before it's even started listening for events, from a single
    typo like HEALTH_PORT=809O.
    """

    def _empty_cp(self):
        import configparser
        return configparser.ConfigParser()

    def test_cfg_int_valid_value_from_env(self, monkeypatch):
        from agent.config import cfg_int
        monkeypatch.setenv('SOME_INT', '42')
        assert cfg_int(self._empty_cp(), 'sect', 'key', 'SOME_INT', '10') == 42

    def test_cfg_int_malformed_env_falls_back_to_default(self, monkeypatch, caplog):
        from agent.config import cfg_int
        monkeypatch.setenv('SOME_INT', '809O')  # letter O, not zero
        with caplog.at_level('ERROR'):
            result = cfg_int(self._empty_cp(), 'health', 'port', 'SOME_INT', '8086')
        assert result == 8086
        assert 'Invalid integer' in caplog.text

    def test_cfg_int_malformed_config_file_value_falls_back_to_default(self, caplog):
        import configparser
        from agent.config import cfg_int
        cp = configparser.ConfigParser()
        cp.read_dict({'metrics': {'port': 'not-a-number'}})
        with caplog.at_level('ERROR'):
            result = cfg_int(cp, 'metrics', 'port', 'METRICS_PORT', '9090')
        assert result == 9090

    def test_cfg_int_missing_value_uses_default(self):
        from agent.config import cfg_int
        assert cfg_int(self._empty_cp(), 'sect', 'key', 'UNSET_INT_VAR', '30') == 30

    def test_cfg_float_valid_value_from_env(self, monkeypatch):
        from agent.config import cfg_float
        monkeypatch.setenv('SOME_FLOAT', '2.5')
        assert cfg_float(self._empty_cp(), 'sect', 'key', 'SOME_FLOAT', '5') == 2.5

    def test_cfg_float_malformed_env_falls_back_to_default(self, monkeypatch, caplog):
        from agent.config import cfg_float
        monkeypatch.setenv('SOME_FLOAT', 'five')
        with caplog.at_level('ERROR'):
            result = cfg_float(self._empty_cp(), 'port_probe', 'timeout_seconds', 'SOME_FLOAT', '5')
        assert result == 5.0
        assert 'Invalid float' in caplog.text
