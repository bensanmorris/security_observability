"""
PKCS11/NSS (Java FIPS mode) and generic in-memory-certificate uprobe handlers
for CertificateAnalyzer.

Split out of agent/analyzer.py as part of the monolithic-analyzer file split --
see that module's docstring for the full list of mixins CertificateAnalyzer
composes. _JavaFipsMixin assumes the composing class provides the instance
state set up in CertificateAnalyzer.__init__ (self.filter_self_events,
self.known_certs, self._known_paths/_known_paths_lock, self._recent_client_sni,
self._uprobe_cert_rate_limiter, self._uprobe_rate_limit_log_lock/
_uprobe_rate_limit_last_log_time/_uprobe_rate_limit_dropped_since_log,
self.metrics, self.kafka_publisher, self.last_event_time) and methods from its
sibling mixins (self._resolve_process_binary, self._is_self_event,
self.extract_certificate_info, self._apply_pod_context,
self.log_certificate_status, self._update_cache_metrics).
"""
import logging
import time
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Logger name is hardcoded (not __name__) so log records from this mixin keep
# reporting under "agent.analyzer" -- test_cert_analyzer.py scopes several
# caplog.at_level(..., logger="agent.analyzer") captures against that exact
# name, and every method here is logically still part of CertificateAnalyzer.
logger = logging.getLogger("agent.analyzer")


class _JavaFipsMixin:
    """
    PKCS11/NSS helpers (Java FIPS mode) plus the generic in-memory-DER-bytes
    uprobe handler. Mixed into CertificateAnalyzer -- see module docstring.
    """

    def _log_rate_limited_uprobe_cert(self, synthetic_path: str) -> None:
        """
        Log a uprobe-cert rate-limit hit at most once every 10 seconds, with
        a count of how many were dropped in between -- mirrors
        _log_rate_limited_new_cert's throttling in agent/retry_queue.py, kept
        as a separate counter/lock here since these are a different trigger
        (uprobe captures, not file discovery) and shouldn't share one
        dropped-count with it.
        """
        with self._uprobe_rate_limit_log_lock:
            self._uprobe_rate_limit_dropped_since_log += 1
            now = time.monotonic()
            if now - self._uprobe_rate_limit_last_log_time < 10.0:
                return
            dropped = self._uprobe_rate_limit_dropped_since_log
            self._uprobe_rate_limit_dropped_since_log = 0
            self._uprobe_rate_limit_last_log_time = now
        logger.warning(
            f"Uprobe-cert analysis rate limit reached (most recently for {synthetic_path}) -- "
            f"{dropped} uprobe capture(s) skipped in the last ~10s. Tune via "
            f"[certificates] uprobe_cert_events_per_second in cert-analyzer.conf or "
            f"UPROBE_CERT_EVENTS_PER_SECOND."
        )

    @staticmethod
    def _read_process_memory(pid: int, address: int, size: int) -> Optional[bytes]:
        """Read bytes from a process's virtual address space via /proc/<pid>/mem.

        Requires CAP_SYS_PTRACE (or the same UID as the target process when
        YAMA ptrace restrictions are relaxed).  cert_analyzer typically runs as
        root in the Tetragon security-monitoring context, so this works.
        """
        if address == 0 or size == 0:
            return None
        try:
            with open(f"/proc/{pid}/mem", "rb") as f:
                f.seek(address)
                return f.read(size)
        except (IOError, OSError, OverflowError) as exc:
            logger.debug(f"Cannot read /proc/{pid}/mem at 0x{address:x} ({size}B): {exc}")
            return None

    def _handle_nsc_create_object(self, event) -> bool:
        """Handle a NSC_CreateObject uprobe event from libsoftokn3.so.

        NSC_CreateObject(session, pTemplate, ulCount, phObject) is called when
        the NSS PKCS11 token creates any object — keys, digest sessions, and
        certificates (CKA_CLASS = CKO_CERTIFICATE = 0x01).

        When Java runs under FIPS mode, KeyStore.setCertificateEntry() calls this
        function to import a certificate DER blob into the NSS FIPS token.  The
        cert bytes live inside the CK_ATTRIBUTE pTemplate array:

            struct CK_ATTRIBUTE {          // 24 bytes on LP64
                uint64 type;               // e.g. 0x01 = CKA_CLASS, 0x11 = CKA_VALUE
                void  *pValue;             // pointer to the attribute's value
                uint64 ulValueLen;         // byte length of *pValue
            };

        Tetragon captures pTemplate and ulCount as uint64 args (args[1] and args[2]).
        This method reads the template from /proc/<pid>/mem, locates CKA_CLASS and
        CKA_VALUE, verifies the object is a certificate, then follows the CKA_VALUE
        pValue pointer to extract the raw DER bytes.
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)
        tetragon_pod = uprobe.process.pod if uprobe.process.HasField('pod') else None
        namespace = tetragon_pod.namespace if tetragon_pod else ""
        parent_process = uprobe.parent.binary if uprobe.HasField('parent') else ""
        parent_pid = uprobe.parent.pid.value if uprobe.HasField('parent') and uprobe.parent.HasField('pid') else 0

        if self.filter_self_events and self._is_self_event(process_name, pid):
            return False

        # Extract the three uint64 args: session, pTemplate, ulCount
        uint64_args = [arg.size_arg for arg in uprobe.args if arg.HasField('size_arg')]
        if len(uint64_args) < 3:
            logger.debug("NSC_CreateObject: fewer than 3 uint64 args, skipping")
            return False

        template_addr = uint64_args[1]
        count = uint64_args[2]

        if count == 0 or count > 64:
            logger.debug(f"NSC_CreateObject: implausible attribute count {count}, skipping")
            return False

        # Read the flat CK_ATTRIBUTE array (each entry is 24 bytes)
        template_bytes = self._read_process_memory(pid, template_addr, count * 24)
        if not template_bytes or len(template_bytes) < count * 24:
            logger.debug(f"NSC_CreateObject: could not read template from PID {pid}")
            return False

        CKA_CLASS = 0x00000001
        CKO_CERTIFICATE = 0x00000001
        CKA_VALUE = 0x00000011
        ATTR_SIZE = 24  # sizeof(CK_ATTRIBUTE) on LP64

        ck_class: Optional[int] = None
        der_addr: Optional[int] = None
        der_len: int = 0

        for i in range(count):
            off = i * ATTR_SIZE
            attr_type = int.from_bytes(template_bytes[off:off+8], 'little')
            p_value   = int.from_bytes(template_bytes[off+8:off+16], 'little')
            val_len   = int.from_bytes(template_bytes[off+16:off+24], 'little')

            if attr_type == CKA_CLASS and val_len in (4, 8):
                class_bytes = self._read_process_memory(pid, p_value, val_len)
                if class_bytes:
                    ck_class = int.from_bytes(class_bytes[:val_len], 'little')
            elif attr_type == CKA_VALUE and val_len > 0:
                der_addr = p_value
                der_len  = val_len

        if ck_class != CKO_CERTIFICATE:
            logger.debug(f"NSC_CreateObject from {process_name}: CKA_CLASS={ck_class:#x}, not a cert")
            return False

        if not der_addr or not (64 < der_len < 65536):
            logger.debug(f"NSC_CreateObject from {process_name}: no CKA_VALUE or implausible len {der_len}")
            return False

        der_bytes = self._read_process_memory(pid, der_addr, der_len)
        if not der_bytes:
            logger.debug(f"NSC_CreateObject: could not read DER bytes from PID {pid}")
            return False

        try:
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        except Exception as exc:
            logger.debug(f"NSC_CreateObject: DER parse failed: {exc}")
            return False

        serial = str(cert.serial_number)
        synthetic_path = f"uprobe://NSC_CreateObject/{pid}/{serial}"

        self.last_event_time = time.time()
        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(self.last_event_time)
        logger.info(
            f"🔍 Detected Java FIPS in-memory certificate: {synthetic_path} "
            f"by {process_name} (PID: {pid})"
        )

        with self._known_paths_lock:
            already_known = synthetic_path in self._known_paths
        if already_known:
            logger.info(f"Re-detected known Java FIPS certificate: {synthetic_path}")
            return True

        # Bypasses _analyze_and_finish_new_certificate_file's file-oriented
        # rate limiter/retry queue -- this isn't a file, and a throttled
        # capture can't be usefully "replayed" later (the bytes only existed
        # transiently in the discovering process's memory) -- but is gated by
        # its own _uprobe_cert_rate_limiter instead. The _known_paths dedup
        # above only catches an *identical* replay: a compromised or
        # malicious process on the node can call NSC_CreateObject with a
        # freshly forged certificate (a different serial every time) as fast
        # as it likes, trivially defeating that dedup, so without a
        # throughput ceiling here this path had no bound on how much
        # extract_certificate_info/logging/Kafka-publish cost it could force
        # per second.
        if not self._uprobe_cert_rate_limiter.try_acquire():
            self._log_rate_limited_uprobe_cert(synthetic_path)
            self.metrics.cert_analysis_errors.labels(error_type='uprobe_rate_limited', node_name=self.metrics._node_name).inc()
            return False

        cert_info = self.extract_certificate_info(cert, synthetic_path, process_name, pid, namespace)
        if cert_info is None:
            return False

        self._apply_pod_context(cert_info, tetragon_pod)
        cert_info.node_name      = event.node_name
        cert_info.parent_process = parent_process
        cert_info.parent_pid     = parent_pid
        self.metrics.update_certificate_metrics(cert_info)
        self.log_certificate_status(cert_info)
        self.known_certs[cert_info.unique_key] = cert_info

        if self.kafka_publisher is not None:
            self.kafka_publisher.publish(cert_info)

        self._update_cache_metrics()
        return True

    def _handle_nsc_find_objects_init(self, event) -> bool:
        """Handle a NSC_FindObjectsInit uprobe event from libsoftokn3.so.

        This fires when Java enumerates objects in the NSS PKCS11 token, which
        happens during KeyStore.load() in FIPS mode.  The template may contain
        a CKO_CERTIFICATE class filter, indicating a cert-read operation.

        We cannot extract cert bytes here (they are returned by subsequent
        NSC_FindObjects + NSC_GetAttributeValue calls), but we log the event
        to show that Java FIPS cert enumeration was detected.
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)

        if self.filter_self_events and self._is_self_event(process_name, pid):
            return False

        uint64_args = [arg.size_arg for arg in uprobe.args if arg.HasField('size_arg')]
        if len(uint64_args) < 3:
            return False

        template_addr = uint64_args[1]
        count = uint64_args[2]

        if count == 0 or count > 32:
            return False

        template_bytes = self._read_process_memory(pid, template_addr, count * 24)
        if not template_bytes:
            return False

        CKA_CLASS = 0x00000001
        CKO_CERTIFICATE = 0x00000001
        ATTR_SIZE = 24

        for i in range(count):
            off = i * ATTR_SIZE
            attr_type = int.from_bytes(template_bytes[off:off+8], 'little')
            p_value   = int.from_bytes(template_bytes[off+8:off+16], 'little')
            val_len   = int.from_bytes(template_bytes[off+16:off+24], 'little')

            if attr_type == CKA_CLASS and val_len in (4, 8):
                class_bytes = self._read_process_memory(pid, p_value, val_len)
                if class_bytes:
                    ck_class = int.from_bytes(class_bytes[:val_len], 'little')
                    if ck_class == CKO_CERTIFICATE:
                        logger.info(
                            f"🔍 Java FIPS cert enumeration: NSC_FindObjectsInit "
                            f"from {process_name} (PID: {pid}) — "
                            f"cert bytes in subsequent NSC_GetAttributeValue"
                        )
                        return True
        return False

    def _handle_ssl_ctrl_sni_capture(self, event) -> bool:
        """
        Handle an SSL_ctrl(cmd==SSL_CTRL_SET_TLSEXT_HOSTNAME) uprobe event --
        the real SNI hostname a client process is about to send, captured
        just before its own TLS handshake (the openssl3-cert-load policy's
        matchArgs already filtered to cmd==55 at the eBPF layer, so every
        event reaching here carries a hostname, not some other SSL_ctrl use).

        Records pid -> (hostname, now) in self._recent_client_sni for
        connect-probe (_probe_and_ingest_tls_cert) to consult instead of the
        raw destination IP. Never extracts or publishes a certificate -- this
        event carries a hostname, not cert bytes. Returns True if a hostname
        was captured, False otherwise (no string_arg, event malformed, etc.).
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)

        if self.filter_self_events and self._is_self_event(process_name, pid):
            return False

        hostname = None
        for arg in uprobe.args:
            if arg.HasField('string_arg'):
                hostname = arg.string_arg
                break

        if not hostname or not pid:
            return False

        self._recent_client_sni[pid] = (hostname, time.monotonic())
        logger.debug(f"Captured real SNI hostname '{hostname}' for PID {pid} ({process_name})")
        return True

    def _handle_uprobe_in_memory_cert(self, event) -> bool:
        """
        Handle a process_uprobe event where the cert arrives as raw DER bytes
        (e.g. SSL_CTX_use_certificate_ASN1). Returns True if a cert was
        successfully extracted and processed, False otherwise (no bytes_arg,
        unparseable bytes, etc.).
        """
        if not event.HasField('process_uprobe'):
            return False

        uprobe = event.process_uprobe
        pid = uprobe.process.pid.value if uprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(uprobe.process.binary, pid)
        tetragon_pod = uprobe.process.pod if uprobe.process.HasField('pod') else None
        namespace = tetragon_pod.namespace if tetragon_pod else ""
        parent_process = uprobe.parent.binary if uprobe.HasField('parent') else ""
        parent_pid = uprobe.parent.pid.value if uprobe.HasField('parent') and uprobe.parent.HasField('pid') else 0

        if self.filter_self_events and self._is_self_event(process_name, pid):
            logger.debug(f"Skipping self-generated uprobe bytes event from {process_name} (PID {pid})")
            return False

        raw_bytes = None
        for arg in uprobe.args:
            if arg.HasField('bytes_arg'):
                raw_bytes = bytes(arg.bytes_arg)
                break

        if not raw_bytes:
            return False

        try:
            cert = x509.load_der_x509_certificate(raw_bytes, default_backend())
        except Exception as e:
            logger.debug(f"Could not parse uprobe bytes_arg as DER certificate: {e}")
            return False

        serial = str(cert.serial_number)
        symbol = uprobe.symbol if uprobe.symbol else "undetermined_symbol_name"
        synthetic_path = f"uprobe://{symbol}/{pid}/{serial}"

        self.last_event_time = time.time()
        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(self.last_event_time)
        logger.info(f"🔍 Detected in-memory certificate: {synthetic_path} by {process_name} (PID: {pid})")

        with self._known_paths_lock:
            already_known = synthetic_path in self._known_paths
        if already_known:
            logger.info(f"Re-detected known in-memory certificate: {synthetic_path}")
            return True

        # Bypasses _analyze_and_finish_new_certificate_file's file-oriented
        # rate limiter/retry queue but is gated by its own
        # _uprobe_cert_rate_limiter -- see the identical comment in
        # _handle_nsc_create_object. In-memory DER captures (e.g. via
        # SSL_CTX_use_certificate_ASN1) are dedup'd only by pid+serial, which
        # a compromised/malicious process can trivially defeat by forging a
        # different serial on every call.
        if not self._uprobe_cert_rate_limiter.try_acquire():
            self._log_rate_limited_uprobe_cert(synthetic_path)
            self.metrics.cert_analysis_errors.labels(error_type='uprobe_rate_limited', node_name=self.metrics._node_name).inc()
            return False

        cert_info = self.extract_certificate_info(cert, synthetic_path, process_name, pid, namespace)
        if cert_info is None:
            return False

        self._apply_pod_context(cert_info, tetragon_pod)
        cert_info.node_name      = event.node_name
        cert_info.parent_process = parent_process
        cert_info.parent_pid     = parent_pid
        self.metrics.update_certificate_metrics(cert_info)
        self.log_certificate_status(cert_info)
        self.known_certs[cert_info.unique_key] = cert_info

        if self.kafka_publisher is not None:
            self.kafka_publisher.publish(cert_info)

        self._update_cache_metrics()
        return True
