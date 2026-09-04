"""
Certificate parsing (PEM/DER/JKS/PKCS12) and info-extraction for
CertificateAnalyzer, plus the large-file routing heuristics.

Split out of agent/analyzer.py as part of the monolithic-analyzer file split --
see that module's docstring for the full list of mixins CertificateAnalyzer
composes. _CertParsingMixin assumes the composing class provides the instance
state set up in CertificateAnalyzer.__init__ (self.CERT_EXTENSIONS,
self.JKS_EXTENSIONS, self.PKCS12_EXTENSIONS, self.password_failed_paths,
self.metrics, self.checksum_enabled, self.spki_hash_enabled,
self.fips_compliance_enabled, self._large_file_byte_cap,
self._large_file_cert_threshold) and the _update_cache_metrics method from
the core class.
"""
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import _EKU_NAMES
from .fips_compliance_checker import (
    extract_key_info as _extract_key_info,
    FipsComplianceResult,
)
from .models import CertificateInfo

# Logger name is hardcoded (not __name__) so log records from this mixin keep
# reporting under "agent.analyzer" -- see the identical note in java_fips.py.
logger = logging.getLogger("agent.analyzer")


class _CertParsingMixin:
    """
    Certificate file parsing (PEM/DER/JKS/PKCS12), per-cert info extraction,
    and the large-file background-thread routing heuristics. Mixed into
    CertificateAnalyzer -- see module docstring.
    """

    # Matches PEM certificate blocks in parse_certificates. Compiled once at
    # class-definition time instead of per-call -- this runs on every small
    # cert-file event on the single-threaded event-consumer loop.
    _PEM_CERT_PATTERN = re.compile(
        b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
        re.DOTALL,
    )

    def is_cert_path(self, path: str) -> bool:
        """Check if a path looks like a certificate or keystore file"""
        if not path:
            return False
        suffix = Path(path).suffix.lower()
        return (suffix in self.CERT_EXTENSIONS
                or suffix in self.JKS_EXTENSIONS
                or suffix in self.PKCS12_EXTENSIONS)

    def parse_jks_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """
        Parse X.509 certificates from a JKS (Java KeyStore) file.

        JKS keystores are used by Java applications (Spring Boot, Tomcat, etc.)
        and contain trusted certificate entries and/or private key entries with
        certificate chains. This method extracts both.

        Requires the 'pyjks' package. Falls back gracefully if not installed.
        Set the JKS_PASSWORD env var if the keystore uses a non-default password.

        Password strategy: tries JKS_PASSWORD env var (if set), then 'changeit'
        (Java ecosystem default), then empty string (unprotected truststores).
        Files that fail all attempts are cached in password_failed_paths so
        subsequent Tetragon events for the same file skip the expensive crypto
        operations rather than retrying on every access.
        """
        # Read JKS_AVAILABLE/jks off agent.analyzer dynamically (deferred
        # import to dodge a top-level circular import) rather than importing
        # them directly here: test_cert_analyzer.py monkeypatches both via
        # agent.analyzer.JKS_AVAILABLE / agent.analyzer.jks, and that patch
        # has no effect on a separate top-level binding in this file's own
        # namespace.
        from . import analyzer as _analyzer_module

        if not _analyzer_module.JKS_AVAILABLE:
            logger.warning(
                f"Skipping JKS file {cert_path}: pyjks not installed. "
                "Add 'pyjks' to requirements.txt to enable JKS support."
            )
            self.metrics.cert_analysis_errors.labels(error_type='jks_unavailable', node_name=self.metrics._node_name).inc()
            return []

        # Skip files that have already failed — avoids repeating crypto work on
        # every subsequent Tetragon event for the same keystore
        if cert_path in self.password_failed_paths:
            logger.debug(
                f"Skipping previously password-failed JKS: {cert_path} "
                f"(set JKS_PASSWORD env var to enable monitoring of this file)"
            )
            return []

        jks = _analyzer_module.jks
        configured = os.getenv('JKS_PASSWORD', '')
        # Option B: env var → changeit → empty string only
        # 'changeit' is retained as it is the Java ecosystem default and present
        # in many managed environments on legacy or CA bundle keystores.
        passwords_to_try = list(dict.fromkeys([configured, 'changeit', '']))

        ks = None
        for password in passwords_to_try:
            try:
                ks = jks.KeyStore.load(cert_path, password)
                logger.debug(
                    f"Opened JKS {cert_path} "
                    f"(password={'<empty>' if not password else '<set>'})"
                )
                break
            except jks.util.BadKeystoreFormatException:
                logger.debug(f"Not a valid JKS keystore: {cert_path}")
                return []
            except Exception:
                continue  # nosec B112 - trying the next candidate password, not swallowing a real error

        if ks is None:
            logger.warning(
                f"Could not open JKS {cert_path}: all passwords failed. "
                "Set JKS_PASSWORD env var if the keystore uses a custom password."
            )
            self.metrics.cert_analysis_errors.labels(error_type='jks_password_failed', node_name=self.metrics._node_name).inc()
            self.password_failed_paths.add(cert_path)
            self._update_cache_metrics()
            return []

        certificates = []

        # Trusted certificate entries (truststore / cacerts style)
        for alias, entry in ks.certs.items():
            try:
                cert = x509.load_der_x509_certificate(entry.cert, default_backend())
                certificates.append(cert)
                logger.debug(f"JKS trusted cert: alias='{alias}' path={cert_path}")
            except Exception as e:
                logger.debug(f"JKS: failed to parse trusted cert alias='{alias}': {e}")

        # Private key entries — extract the certificate chain
        for alias, entry in ks.private_keys.items():
            for _, cert_der in entry.cert_chain:
                try:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    certificates.append(cert)
                    logger.debug(f"JKS chain cert: alias='{alias}' path={cert_path}")
                except Exception as e:
                    logger.debug(f"JKS: failed to parse chain cert alias='{alias}': {e}")

        logger.debug(f"JKS: loaded {len(certificates)} certificate(s) from {cert_path}")
        return certificates

    def parse_pkcs12_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """
        Parse X.509 certificates from a PKCS12 keystore (.p12 / .pfx).

        PKCS12 is the modern industry-standard keystore format (replacing JKS)
        and is used by Java apps, .NET, OpenSSL, and browsers. A PKCS12 file
        contains a leaf certificate, its private key, and optionally a chain of
        intermediate/root CA certificates.

        No additional dependencies are required — the 'cryptography' library
        already provides PKCS12 support via load_pkcs12().

        Set the PKCS12_PASSWORD env var if the file uses a non-default password.
        """
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12

        configured = os.getenv('PKCS12_PASSWORD', '')
        # Option B: env var → changeit → empty string only
        passwords_to_try = list(dict.fromkeys([configured, 'changeit', '']))

        # Skip files that have already failed password attempts
        if cert_path in self.password_failed_paths:
            logger.debug(
                f"Skipping previously password-failed PKCS12: {cert_path} "
                f"(set PKCS12_PASSWORD env var to enable monitoring of this file)"
            )
            return []

        try:
            with open(cert_path, 'rb') as f:
                p12_data = f.read()
        except FileNotFoundError:
            logger.debug(f"PKCS12 file not found: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='file_not_found', node_name=self.metrics._node_name).inc()
            return []
        except PermissionError:
            logger.debug(f"Permission denied reading PKCS12: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='permission_denied', node_name=self.metrics._node_name).inc()
            return []

        p12 = None
        for password in passwords_to_try:
            try:
                pw_bytes = password.encode() if password else b''
                p12 = load_pkcs12(p12_data, pw_bytes)
                logger.debug(
                    f"Opened PKCS12 {cert_path} "
                    f"(password={'<empty>' if not password else '<set>'})"
                )
                break
            except Exception:
                continue  # nosec B112 - trying the next candidate password, not swallowing a real error

        if p12 is None:
            logger.warning(
                f"Could not open PKCS12 {cert_path}: all passwords failed. "
                "Set PKCS12_PASSWORD env var if the file uses a custom password."
            )
            self.metrics.cert_analysis_errors.labels(error_type='pkcs12_password_failed', node_name=self.metrics._node_name).inc()
            self.password_failed_paths.add(cert_path)
            self._update_cache_metrics()
            return []

        certificates = []

        # Leaf certificate (the primary end-entity cert)
        if p12.cert and p12.cert.certificate:
            certificates.append(p12.cert.certificate)
            logger.debug(f"PKCS12 leaf cert: path={cert_path}")

        # Additional certificates — intermediate and root CAs in the chain
        if p12.additional_certs:
            for additional in p12.additional_certs:
                if additional.certificate:
                    certificates.append(additional.certificate)
                    logger.debug(f"PKCS12 chain cert: path={cert_path}")

        logger.debug(f"PKCS12: loaded {len(certificates)} certificate(s) from {cert_path}")
        return certificates

    def parse_certificates(self, cert_path: str) -> List[x509.Certificate]:
        """
        Parse ALL X.509 certificates from a file (supports PEM, DER, JKS, and PKCS12)

        cert_path comes straight from a Tetragon-reported file path, filtered
        only by extension — nothing upstream checks the actual filesystem
        entry type. This is the single entry point all three format branches
        below go through before opening the file (JKS via jks.KeyStore.load,
        PKCS12 and PEM/DER via plain open()), so one is_file() guard here
        protects all of them from blocking on a FIFO with no writer (open()
        on a FIFO blocks indefinitely per POSIX named-pipe semantics) — this
        runs on the single-threaded event-consumer loop for every new small
        file, so a block here hangs cert event processing entirely. See
        _count_pem_certs for the same guard on the large-file routing check.
        """
        suffix = Path(cert_path).suffix.lower()

        if not Path(cert_path).is_file():
            logger.debug(f"Skipping non-regular-file cert path: {cert_path}")
            return []

        if suffix in self.JKS_EXTENSIONS:
            return self.parse_jks_certificates(cert_path)

        if suffix in self.PKCS12_EXTENSIONS:
            return self.parse_pkcs12_certificates(cert_path)

        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()

            certificates = []

            # Try PEM format first (can contain multiple certs)
            try:
                pem_certs = self._PEM_CERT_PATTERN.findall(cert_data)

                if pem_certs:
                    for pem_cert in pem_certs:
                        try:
                            cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                            certificates.append(cert)
                        except Exception as e:
                            logger.debug(f"Failed to parse PEM cert in {cert_path}: {e}")

                    if certificates:
                        logger.debug(f"Loaded {len(certificates)} certificate(s) from {cert_path}")
                        return certificates

            except Exception as e:
                logger.debug(f"PEM parsing failed for {cert_path}: {e}")

            # Try DER format (single certificate)
            try:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
                return [cert]
            except Exception:
                pass  # nosec B110 - neither PEM (logged above) nor DER matched; return [] below, not a hidden error

            return []

        except FileNotFoundError:
            logger.debug(f"Certificate file not found: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='file_not_found', node_name=self.metrics._node_name).inc()
            return []
        except PermissionError:
            logger.debug(f"Permission denied reading certificate: {cert_path}")
            self.metrics.cert_analysis_errors.labels(error_type='permission_denied', node_name=self.metrics._node_name).inc()
            return []
        except Exception as e:
            logger.debug(f"Error reading certificate {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='read_error', node_name=self.metrics._node_name).inc()
            return []

    def extract_certificate_info(
        self,
        cert: x509.Certificate,
        cert_path: str,
        process: str,
        pid: int,
        namespace: str = "",
        cert_index: int = 0
    ) -> Optional[CertificateInfo]:
        """
        Extract relevant information from an X.509 certificate.

        Returns None if any mandatory field cannot be extracted, rather than
        raising — the caller in analyze_certificate() handles None gracefully.
        This covers malformed certs, encrypted fields, and future cryptography
        library API changes.
        """
        try:
            subject = cert.subject.rfc4514_string()
        except Exception as e:
            logger.warning(f"Could not extract subject from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=self.metrics._node_name).inc()
            return None

        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception as e:
            logger.warning(f"Could not extract issuer from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=self.metrics._node_name).inc()
            return None

        try:
            serial_number = str(cert.serial_number)
        except Exception as e:
            logger.warning(f"Could not extract serial number from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=self.metrics._node_name).inc()
            return None

        # Use the UTC-aware property where available, fall back to the naive
        # deprecated property for older cryptography library versions
        try:
            not_before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before
            not_after  = getattr(cert, 'not_valid_after_utc',  None) or cert.not_valid_after
            # Strip timezone info to keep datetime arithmetic consistent with
            # the rest of the codebase which uses datetime.utcnow()
            if not_before and not_before.tzinfo is not None:
                not_before = not_before.replace(tzinfo=None)
            if not_after and not_after.tzinfo is not None:
                not_after = not_after.replace(tzinfo=None)
        except Exception as e:
            logger.warning(f"Could not extract validity dates from cert {cert_index} in {cert_path}: {e}")
            self.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=self.metrics._node_name).inc()
            return None

        try:
            common_name_attrs = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            common_name = common_name_attrs[0].value if common_name_attrs else ""
        except Exception:
            common_name = ""

        san_dns_names = []
        san_ip_addresses = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            san_ip_addresses = [
                str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)
            ]
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting SAN: {e}")

        key_usage = None
        try:
            ku_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.KEY_USAGE
            )
            ku = ku_ext.value
            flags = [
                'digital_signature', 'content_commitment', 'key_encipherment',
                'data_encipherment', 'key_agreement', 'key_cert_sign', 'crl_sign',
            ]
            key_usage = [f for f in flags if getattr(ku, f)]
            if ku.key_agreement:
                if ku.encipher_only:
                    key_usage.append('encipher_only')
                if ku.decipher_only:
                    key_usage.append('decipher_only')
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Key Usage: {e}")

        extended_key_usage = None
        try:
            eku_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            )
            extended_key_usage = [
                _EKU_NAMES.get(oid.dotted_string, oid.dotted_string)
                for oid in eku_ext.value
            ]
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Extended Key Usage: {e}")

        is_ca = None
        basic_constraints_path_length = None
        try:
            bc_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.BASIC_CONSTRAINTS
            )
            is_ca = bc_ext.value.ca
            basic_constraints_path_length = bc_ext.value.path_length
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Basic Constraints: {e}")

        ocsp_responder_urls = None
        ca_issuers_urls = None
        try:
            aia_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            ocsp_responder_urls = []
            ca_issuers_urls = []
            for desc in aia_ext.value:
                if not isinstance(desc.access_location, x509.UniformResourceIdentifier):
                    continue  # access_location is a GeneralName; only the URI form is meaningful here
                url = desc.access_location.value
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    ocsp_responder_urls.append(url)
                elif desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                    ca_issuers_urls.append(url)
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug(f"Error extracting Authority Information Access: {e}")

        # A certificate is self-signed when its subject name matches its issuer
        # and the signature verifies against its own public key.
        # verify_directly_issued_by() (cryptography ≥40) performs both checks atomically;
        # on older versions (e.g. RHEL8 ships 3.2.1) fall back to name-match heuristic.
        is_self_signed = False
        try:
            cert.verify_directly_issued_by(cert)
            is_self_signed = True
        except AttributeError:
            # cryptography < 40: Name.__eq__ does proper attribute-set comparison.
            is_self_signed = cert.subject == cert.issuer
        except Exception:
            # nosec B110 - verify_directly_issued_by() raises whenever the cert
            # isn't (directly) self-signed; that's the expected negative case,
            # not an error, so is_self_signed correctly stays False.
            pass

        # Compute SHA-256 of DER-encoded certificate when enabled.
        # Uses public_bytes() which is always available for a parsed cert object.
        checksum = ""
        if self.checksum_enabled:
            try:
                der_bytes = cert.public_bytes(Encoding.DER)
                checksum = hashlib.sha256(der_bytes).hexdigest()
            except Exception as e:
                logger.debug(f"Could not compute checksum for cert {cert_index} in {cert_path}: {e}")

        # Public key object -- extracted once and reused below for the SPKI
        # hash, key-info extraction, and (when enabled) the FIPS check,
        # rather than re-parsing it per consumer. cert.public_key() does
        # real ASN.1/crypto work, so this avoids doing it twice per cert.
        try:
            pub_key = cert.public_key()
        except Exception as e:
            logger.debug(f"Could not extract public key for cert {cert_index} in {cert_path}: {e}")
            pub_key = None

        # Compute SHA-256 of the DER-encoded SubjectPublicKeyInfo (public key
        # only) when enabled. Unlike `checksum` above, this value is identical
        # across a renewal that reuses the same key pair -- that's what makes
        # it useful for downstream "key reuse detected" analysis, which is
        # done outside the analyzer by comparing this field across successive
        # discoveries of the same logical certificate.
        spki_hash = ""
        if self.spki_hash_enabled and pub_key is not None:
            try:
                spki_der = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
                spki_hash = hashlib.sha256(spki_der).hexdigest()
            except Exception as e:
                logger.debug(f"Could not compute SPKI hash for cert {cert_index} in {cert_path}: {e}")

        # spki_algorithm_oid/signature_algorithm_oid and the FIPS check below
        # read _get_algorithm_oids/_fips_check off agent.analyzer dynamically
        # (deferred import to dodge a top-level circular import) rather than
        # the top-level import this file would otherwise use directly:
        # test_cert_analyzer.py monkeypatches both via
        # agent.analyzer._get_algorithm_oids / agent.analyzer._fips_check, and
        # that patch has no effect on a separate binding in this file's own
        # namespace.
        from . import analyzer as _analyzer_module

        # Raw SPKI / signature algorithm OIDs -- captured unconditionally
        # (cheap, and unlike the FIPS fields below these still resolve for
        # algorithm types this install of `cryptography` can't instantiate
        # as a key object, e.g. post-quantum/composite keys).
        try:
            spki_algorithm_oid, signature_algorithm_oid = _analyzer_module._get_algorithm_oids(cert)
        except Exception as e:
            logger.debug(f"Could not extract algorithm OIDs for cert {cert_index} in {cert_path}: {e}")
            spki_algorithm_oid, signature_algorithm_oid = '', ''

        # Key algorithm/size/curve/signature-hash -- extracted unconditionally
        # (cheap, like the algorithm OIDs above) so dashboards/inventory get
        # real key metadata regardless of whether FIPS compliance *checking*
        # is enabled. FIPS compliance itself (fips_compliant/fips_violations
        # below) evaluates this same key info against FIPS 140-2/140-3
        # requirements and stays gated behind fips_compliance_enabled -- that
        # judgement is the genuinely optional part, not the key metadata.
        key_info = _extract_key_info(cert, pub_key=pub_key)

        fips_result = None
        if self.fips_compliance_enabled:
            try:
                fips_result = _analyzer_module._fips_check(cert, pub_key=pub_key, key_info=key_info)
            except Exception as e:
                logger.debug(f"FIPS check failed for cert {cert_index} in {cert_path}: {e}")
                fips_result = FipsComplianceResult(
                    compliant=False, key_algorithm=key_info.key_algorithm,
                    key_size=key_info.key_size, curve_name=key_info.curve_name,
                    signature_hash=key_info.signature_hash,
                    violations=['FIPS check error'],
                )

        return CertificateInfo(
            path=cert_path,
            subject=subject,
            issuer=issuer,
            serial_number=serial_number,
            not_before=not_before,
            not_after=not_after,
            process=process,
            pid=pid,
            namespace=namespace,
            common_name=common_name,
            san_dns_names=san_dns_names,
            san_ip_addresses=san_ip_addresses,
            cert_index=cert_index,
            checksum=checksum,
            spki_hash=spki_hash,
            key_algorithm=key_info.key_algorithm,
            key_size=key_info.key_size,
            signature_hash=key_info.signature_hash,
            curve_name=key_info.curve_name,
            fips_checked=fips_result is not None,
            fips_compliant=fips_result.compliant if fips_result is not None else False,
            fips_violations=fips_result.violations if fips_result is not None else [],
            spki_algorithm_oid=spki_algorithm_oid,
            signature_algorithm_oid=signature_algorithm_oid,
            key_usage=key_usage,
            extended_key_usage=extended_key_usage,
            ocsp_responder_urls=ocsp_responder_urls,
            ca_issuers_urls=ca_issuers_urls,
            is_ca=is_ca,
            basic_constraints_path_length=basic_constraints_path_length,
            is_self_signed=is_self_signed,
        )

    def _count_pem_certs(self, cert_path: str) -> int:
        """
        Cheap upper-bound estimate of how many certificates a file contains —
        used only to decide whether parsing should be deferred to a background
        thread. Counts PEM 'BEGIN CERTIFICATE' markers without doing any ASN.1
        parsing, which is orders of magnitude cheaper than parse_certificates()
        for files with hundreds of certs (e.g. a system CA trust bundle).

        Only reads the first _large_file_byte_cap bytes rather than the whole
        file — this runs on the Tetragon event-consumer thread (or the
        periodic-scan thread), and an unbounded full-file read here would
        block on, and allocate memory for, any file that merely matches a
        cert extension regardless of its actual size. _large_file_byte_cap
        (default 2MB) comfortably covers real-world bundles: even a generous
        system CA trust store (Mozilla/NSS roots plus enterprise-added ones,
        a few hundred certs) runs a few hundred KB in practice, well under
        the cap, so this doesn't undercount real bundles in the cases that
        matter for the threshold check below.

        JKS/PKCS12 keystores go through a dedicated decoder and always
        return 0 here rather than being counted — see _is_large_certificate_file,
        which gates them on file size instead of routing through this method.

        cert_path comes straight from a Tetragon-reported file path, filtered
        only by extension (is_cert_path) — nothing upstream checks the actual
        filesystem entry type. open() on a FIFO with no writer blocks
        indefinitely (standard POSIX named-pipe semantics), and this runs on
        the single-threaded event-consumer loop, so any unprivileged process
        on the node creating e.g. `mkfifo x.pem` would otherwise hang cert
        event processing forever. is_file() safely returns False for FIFOs/
        sockets/devices (even through a symlink) via a non-blocking stat()
        call, and swallows OSError, so it's the same guard periodic_scan
        already applies before ever reaching a background-thread path.
        """
        suffix = Path(cert_path).suffix.lower()
        if suffix in self.JKS_EXTENSIONS or suffix in self.PKCS12_EXTENSIONS:
            return 0
        if not Path(cert_path).is_file():
            return 0
        try:
            with open(cert_path, 'rb') as f:
                return f.read(self._large_file_byte_cap).count(b'-----BEGIN CERTIFICATE-----')
        except OSError:
            return 0

    def _is_large_certificate_file(self, cert_path: str) -> bool:
        """
        True if cert_path should be parsed on a background thread instead of
        inline on the event-consumer thread. Covers every extension
        is_cert_path() accepts: everything the certificate-file-access
        Tetragon policy watches (.crt/.pem/.cert/.cer, .jks/.keystore/
        .truststore, .p12/.pfx) plus .key, which periodic_scan can discover
        even though no Tetragon policy watches it.

        PEM bundles: counted cheaply via _count_pem_certs (a BEGIN-marker
        scan capped at _large_file_byte_cap bytes) and compared against
        _large_file_cert_threshold — a richer, more precise signal than raw
        size, since real certs cluster around a fairly consistent PEM size.

        Everything else routes through a straight _large_file_byte_cap size
        check instead, via one non-blocking stat() call:

        - JKS/PKCS12: binary keystore formats with no cheap text marker to
          count the way PEM's "-----BEGIN CERTIFICATE-----" allows — an exact
          count would require doing the very parse this gate exists to avoid
          on the hot thread (parse_jks_certificates/parse_pkcs12_certificates
          read and fully decode the file with no size cap of their own).

        - .crt/.cer/.cert files whose content is DER rather than PEM (both
          are valid per parse_certificates' DER fallback, agent/analyzer.py
          load_der_x509_certificate call): _count_pem_certs finds zero PEM
          markers in binary DER content, indistinguishable from a genuinely
          small file — without this fallback, a large DER blob would bypass
          the gate exactly like JKS/PKCS12 used to.

        - .key files: contain a private key, not a certificate, so they
          never contain a "-----BEGIN CERTIFICATE-----" marker either —
          same zero-markers fallback as DER above, no special-casing needed.

        A real keystore or single cert (even a generous truststore with
        hundreds of certs, or DER cert with a large embedded chain) runs a
        few hundred KB in practice, well under the 2MB default, so this
        doesn't route legitimate files to the background path.
        """
        suffix = Path(cert_path).suffix.lower()
        if suffix in self.JKS_EXTENSIONS or suffix in self.PKCS12_EXTENSIONS:
            try:
                return Path(cert_path).stat().st_size > self._large_file_byte_cap
            except OSError:
                return False

        pem_cert_count = self._count_pem_certs(cert_path)
        if pem_cert_count > self._large_file_cert_threshold:
            return True
        if pem_cert_count > 0:
            # At least one real PEM cert found, under the threshold -- a
            # normal small/medium PEM file, sync path as before.
            return False
        # No PEM markers found at all -- either a genuinely tiny/empty file,
        # or binary DER content the text scan can't see. Fall back to size.
        try:
            return Path(cert_path).stat().st_size > self._large_file_byte_cap
        except OSError:
            return False
