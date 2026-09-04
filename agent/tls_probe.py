"""
Port-probe / TLS-probe helpers for CertificateAnalyzer -- port-scanner-like
certificate discovery from bind/connect kprobe events.

Split out of agent/analyzer.py as part of the monolithic-analyzer file split --
see that module's docstring for the full list of mixins CertificateAnalyzer
composes. _TlsProbeMixin assumes the composing class provides the instance
state set up in CertificateAnalyzer.__init__ (self._probed_endpoints,
self._probe_in_flight/_probe_in_flight_lock, self._recent_client_sni,
self._sni_capture_enabled/_sni_capture_window_seconds, self._port_probe_timeout,
self._port_probe_connect_delay, self._tls_outbound_ports, self.known_certs,
self.metrics, self.kafka_publisher, self.last_event_time) and methods/constants
from its sibling mixins and the core class (self._resolve_process_binary,
self._apply_pod_context, self.log_certificate_status, self.extract_certificate_info,
self._update_cache_metrics, self._start_background_thread,
self._SNI_CAPTURE_POLL_INTERVAL_SECONDS, self._SNI_CAPTURE_POLL_MAX_SECONDS).
"""
import logging
import re
import socket
import ssl
import struct
import time
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Logger name is hardcoded (not __name__) so log records from this mixin keep
# reporting under "agent.analyzer" -- see the identical note in java_fips.py.
logger = logging.getLogger("agent.analyzer")


class _TlsProbeMixin:
    """
    Port-probe / TLS-probe helpers (port-scanner-like cert discovery). Mixed
    into CertificateAnalyzer -- see module docstring.
    """

    # Matches a bare-IP fib_trie leaf line in _read_primary_ip_from_fib_trie.
    # Compiled once instead of per-call -- this runs on every TLS bind/connect
    # probe.
    _FIB_TRIE_IP_ONLY_PATTERN = re.compile(r'\|--\s+(\d+\.\d+\.\d+\.\d+)\s*$')

    def _read_primary_ip_from_fib_trie(self, pid: int) -> Optional[str]:
        """Read the primary non-loopback IPv4 from /proc/<pid>/net/fib_trie.

        Follows the process's network namespace so this returns the container's
        own IP, not the host IP. Used to probe containerised services that bind
        to 0.0.0.0 inside their own network namespace.
        """
        try:
            with open(f'/proc/{pid}/net/fib_trie', 'r') as f:
                lines = f.readlines()
        except OSError:
            return None

        # The kernel renders each LOCAL /32 leaf as a bare-IP line ("|-- x.x.x.x")
        # immediately followed by its mask/type line ("/32 host LOCAL") -- the IP
        # and "/32" never share a line, so a single-line regex never matches.
        for prev_line, line in zip(lines, lines[1:]):
            if 'LOCAL' in line and '/32 host' in line:
                m = self._FIB_TRIE_IP_ONLY_PATTERN.search(prev_line)
                if m:
                    ip = m.group(1)
                    if not ip.startswith('127.') and ip != '0.0.0.0':  # nosec B104 - comparing an observed process's bind address, not binding our own socket
                        return ip
        return None

    def _resolve_pid_ip(self, pid: int, bind_addr: str) -> str:
        """Resolve the IP address to probe for a given bind event.

        If the service bound to a specific address, use it directly. For
        wildcard binds (0.0.0.0 / ::) on K8s, read the container's primary
        IP from its network namespace via /proc/<pid>/net/fib_trie. Falls
        back to 127.0.0.1 for bare-metal deployments where the process
        is in the host network namespace.
        """
        if bind_addr and bind_addr not in ('0.0.0.0', '::', ''):  # nosec B104 - comparing an observed process's bind address, not binding our own socket
            return bind_addr
        ip = None
        try:
            ip = self._read_primary_ip_from_fib_trie(pid)
        except Exception as e:
            logger.debug("fib_trie lookup failed for PID %s: %s", pid, e)
        return ip or '127.0.0.1'

    def _await_captured_sni(self, pid: int) -> Optional[str]:
        """Poll self._recent_client_sni for a fresh capture for this PID,
        for up to _SNI_CAPTURE_POLL_MAX_SECONDS, instead of a single
        point-in-time check -- see the constant's own comment for why a
        single check races the SSL_ctrl uprobe event. Runs entirely on the
        caller's own background probe thread. Returns the hostname once a
        capture younger than sni_capture_window_seconds is seen, or None if
        the deadline passes first (never-arriving capture, non-OpenSSL
        client, feature genuinely has nothing for this PID, etc.) -- a
        stale/missing entry is treated the same as "not yet arrived" and
        polling continues, since a longer-lived PID can have a stale entry
        from an earlier connection sitting in the cache right up until this
        connection's own fresh one overwrites it.
        """
        deadline = time.monotonic() + self._SNI_CAPTURE_POLL_MAX_SECONDS
        while True:
            captured = self._recent_client_sni.get(pid)
            if captured is not None:
                real_hostname, captured_at = captured
                if time.monotonic() - captured_at < self._sni_capture_window_seconds:
                    return real_hostname
            if time.monotonic() >= deadline:
                return None
            time.sleep(self._SNI_CAPTURE_POLL_INTERVAL_SECONDS)

    def _probe_tls_endpoint(
        self,
        host: str,
        port: int,
        process_name: str,
        pid: int,
        node_name: str,
        tetragon_pod,
        mechanism: str = 'bind',
    ) -> None:
        """Connect to host:port, complete a TLS handshake, and ingest the leaf cert.

        Uses no-verify mode intentionally — the goal is certificate inventory,
        not validation. A short delay before calling (port_probe_connect_delay)
        gives the service time to finish TLS initialisation after binding.

        mechanism ('bind' or 'connect') identifies which kprobe triggered this
        probe. It's folded into both the synthetic path and the dedup key so
        that a service independently discoverable via both an inbound bind
        and an outbound connect (the same literal host:port) is tracked and
        published as two distinct findings rather than one silently
        swallowing the other — see _handle_tls_bind_event/_handle_tls_connect_event.
        """
        synthetic_path = f'tls-{mechanism}-probe://{host}:{port}'
        endpoint_key = f'{mechanism}:{host}:{port}'

        if endpoint_key in self._probed_endpoints:
            logger.debug("TLS probe: already probed %s", synthetic_path)
            self.metrics.tls_port_probes_total.labels(status='skipped', node_name=self.metrics._node_name).inc()
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # KNOWN LIMITATION (mitigated for 'connect' below when sni_capture_enabled):
        # server_hostname defaults to the raw destination IP, not the real
        # hostname the original process's TLS ClientHello sent -- Tetragon's
        # kprobe only sees L3/L4 (connect()/bind()), fired before any TLS
        # bytes including SNI exist. Harmless against a single-tenant server,
        # but against an SNI-multiplexed CDN edge (Fastly, Cloudflare,
        # CloudFront, ...) an IP-string SNI matches no real customer vhost,
        # so the edge falls back to its own generic default cert instead of
        # the one the real process negotiated. See
        # extras/PRESENTATION-QA.md's "Scale & Performance" section.
        server_hostname = host
        if mechanism == 'connect' and self._sni_capture_enabled:
            real_hostname = self._await_captured_sni(pid)
            if real_hostname is not None:
                server_hostname = real_hostname
                logger.debug(
                    "TLS probe: using captured real SNI '%s' instead of %s for PID %s",
                    real_hostname, host, pid,
                )

        raw_sock = None
        tls_version = None
        cipher_name = None
        try:
            raw_sock = socket.create_connection((host, port), timeout=self._port_probe_timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as ssock:
                raw_sock = None  # SSL socket owns it now; closed by the with-block
                der_bytes = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else None
        except Exception as e:
            logger.debug("TLS probe failed %s:%s: %s", host, port, e)
            self.metrics.tls_port_probes_total.labels(status='failed', node_name=self.metrics._node_name).inc()
            return
        finally:
            if raw_sock is not None:
                raw_sock.close()

        if not der_bytes:
            self.metrics.tls_port_probes_total.labels(status='failed', node_name=self.metrics._node_name).inc()
            return

        try:
            cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        except Exception as e:
            logger.debug("TLS probe: DER parse failed for %s:%s: %s", host, port, e)
            self.metrics.tls_port_probes_total.labels(status='failed', node_name=self.metrics._node_name).inc()
            return

        cert_info = self.extract_certificate_info(cert, synthetic_path, process_name, pid)
        if cert_info is None:
            self.metrics.tls_port_probes_total.labels(status='failed', node_name=self.metrics._node_name).inc()
            return

        if tetragon_pod is not None:
            self._apply_pod_context(cert_info, tetragon_pod)
        cert_info.node_name = node_name

        self.metrics.update_certificate_metrics(cert_info)
        self.log_certificate_status(cert_info)
        self.known_certs[cert_info.unique_key] = cert_info
        # Guarded by _probe_in_flight_lock -- the same lock the event-consumer
        # thread holds while checking "already probed or in flight" before
        # spawning a probe (see _handle_tls_bind_event/_handle_tls_connect_event).
        # This runs on the probe's own background thread, so without the lock
        # this write would race that check. The caller's finally block adds
        # the same key again (alongside its in-flight discard) for the
        # failure path, where this success-only add never runs; the success
        # path's double-add through the same lock is harmless.
        with self._probe_in_flight_lock:
            self._probed_endpoints.add(endpoint_key)
        self._update_cache_metrics()

        if tls_version and cipher_name:
            self.metrics.record_tls_negotiation(cert_info, tls_version, cipher_name)

        if self.kafka_publisher is not None:
            self.kafka_publisher.publish(cert_info)

        self.metrics.tls_port_probes_total.labels(status='success', node_name=self.metrics._node_name).inc()
        logger.info(
            f"TLS probe: discovered cert at {host}:{port} "
            f"CN={cert_info.common_name} process={process_name} "
            f"protocol={tls_version} cipher={cipher_name}"
        )

    def _handle_tls_bind_event(self, event) -> None:
        """Extract the bound address/port from a security_socket_bind or sys_bind
        kprobe event, resolve the probe target IP, and schedule a TLS probe.

        Handles two policy variants:
          - security_socket_bind (experimental policy): sockaddr decoded by Tetragon
            into sockaddr_arg — port in arg[1].sockaddr_arg.port
          - sys_bind (fixed policy): raw sockaddr bytes in arg[1].bytes_arg
        """
        kprobe = event.process_kprobe
        fn = kprobe.function_name
        pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(kprobe.process.binary, pid)
        tetragon_pod = kprobe.process.pod if kprobe.process.HasField('pod') else None
        node_name = event.node_name

        port = 0
        bind_addr = '0.0.0.0'  # nosec B104 - default for an observed process's bind event, not binding our own socket

        if fn == 'security_socket_bind':
            # arg[0]=sock (socket struct), arg[1]=sockaddr_arg (address being bound)
            for arg in kprobe.args:
                if arg.HasField('sockaddr_arg') and arg.sockaddr_arg.port:
                    port = arg.sockaddr_arg.port
                    bind_addr = arg.sockaddr_arg.addr or '0.0.0.0'  # nosec B104 - observed process's bind address, not binding our own socket
                    break

        elif fn == 'sys_bind':
            # arg[0]=int (fd), arg[1]=char_buf (raw sockaddr struct)
            if len(kprobe.args) >= 2 and kprobe.args[1].HasField('bytes_arg'):
                data = bytes(kprobe.args[1].bytes_arg)
                if len(data) >= 8:
                    family = struct.unpack_from('<H', data, 0)[0]
                    port = struct.unpack_from('>H', data, 2)[0]
                    if family == 2:  # AF_INET
                        bind_addr = '.'.join(str(b) for b in data[4:8])

        if not port:
            logger.debug("TLS bind event: could not extract port from %s event", fn)
            return

        host = self._resolve_pid_ip(pid, bind_addr)
        delay = self._port_probe_connect_delay

        self.last_event_time = time.time()
        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(self.last_event_time)

        # Prefixed with the mechanism so an inbound bind and an outbound
        # connect to the exact same host:port are tracked (and published)
        # independently instead of racing for one shared dedup slot — see
        # _probe_tls_endpoint's docstring.
        endpoint_key = f'bind:{host}:{port}'
        with self._probe_in_flight_lock:
            if endpoint_key in self._probed_endpoints or endpoint_key in self._probe_in_flight:
                logger.debug("TLS bind probe: %s already probed or in flight, skipping", endpoint_key)
                return
            self._probe_in_flight.add(endpoint_key)

        def _probe():
            if delay:
                time.sleep(delay)
            try:
                self._probe_tls_endpoint(host, port, process_name, pid, node_name, tetragon_pod, mechanism='bind')
            except Exception as e:
                logger.debug("TLS probe thread error %s:%s: %s", host, port, e)
            finally:
                # discard-from-in-flight and add-to-probed must happen as one
                # atomic step under the same lock — otherwise there's a window
                # where endpoint_key is in neither set, and a second bind event
                # for the same endpoint landing in that window would see it as
                # neither in-flight nor already-probed and spawn a duplicate
                # probe (and duplicate Kafka publish, since _probe_tls_endpoint
                # has no de-dupe of its own against known_certs).
                with self._probe_in_flight_lock:
                    self._probe_in_flight.discard(endpoint_key)
                    self._probed_endpoints.add(endpoint_key)

        started = self._start_background_thread(_probe, name=f'tls-bind-probe-{host}-{port}')
        if not started:
            # _probe's finally never ran, so undo the in-flight marker here —
            # this endpoint will be retried on its next qualifying event.
            with self._probe_in_flight_lock:
                self._probe_in_flight.discard(endpoint_key)
            self.metrics.tls_port_probes_total.labels(status='skipped', node_name=self.metrics._node_name).inc()
            return
        logger.debug(
            "Scheduled TLS probe %s:%s delay=%ss pid=%s process=%s",
            host, port, delay, pid, process_name,
        )

    def _handle_tls_connect_event(self, event) -> None:
        """Extract destination address/port from a tcp_connect kprobe event and schedule a TLS probe.

        tcp_connect fires when a process initiates an outbound TCP connection.
        The sock_arg carries the destination address and port. We probe that
        remote endpoint immediately — no startup delay is needed because the
        remote server is already running when our process connects to it.
        """
        kprobe = event.process_kprobe
        pid = kprobe.process.pid.value if kprobe.process.HasField('pid') else 0
        process_name = self._resolve_process_binary(kprobe.process.binary, pid)
        tetragon_pod = kprobe.process.pod if kprobe.process.HasField('pod') else None
        node_name = event.node_name

        daddr = ''
        dport = 0
        for arg in kprobe.args:
            if arg.HasField('sock_arg'):
                daddr = arg.sock_arg.daddr
                dport = arg.sock_arg.dport
                break

        if not dport or not daddr:
            logger.debug("tcp_connect event: could not extract destination address/port")
            return

        if dport not in self._tls_outbound_ports:
            logger.debug("tcp_connect: skipping non-TLS port %s from %s", dport, process_name)
            return

        self.last_event_time = time.time()
        self.metrics.last_event_timestamp.labels(node_name=self.metrics._node_name).set(self.last_event_time)

        # Prefixed with the mechanism so an outbound connect and an inbound
        # bind to the exact same host:port are tracked (and published)
        # independently instead of racing for one shared dedup slot — see
        # _probe_tls_endpoint's docstring.
        endpoint_key = f'connect:{daddr}:{dport}'
        with self._probe_in_flight_lock:
            if endpoint_key in self._probed_endpoints or endpoint_key in self._probe_in_flight:
                logger.debug("TLS connect probe: %s already probed or in flight, skipping", endpoint_key)
                return
            self._probe_in_flight.add(endpoint_key)

        def _probe():
            try:
                self._probe_tls_endpoint(daddr, dport, process_name, pid, node_name, tetragon_pod, mechanism='connect')
            except Exception as e:
                logger.debug("TLS outbound probe thread error %s:%s: %s", daddr, dport, e)
            finally:
                # discard-from-in-flight and add-to-probed must happen as one
                # atomic step under the same lock — otherwise there's a window
                # where endpoint_key is in neither set, and a second connect
                # event for the same endpoint landing in that window would see
                # it as neither in-flight nor already-probed and spawn a
                # duplicate probe (and duplicate Kafka publish, since
                # _probe_tls_endpoint has no de-dupe of its own against
                # known_certs).
                with self._probe_in_flight_lock:
                    self._probe_in_flight.discard(endpoint_key)
                    self._probed_endpoints.add(endpoint_key)

        started = self._start_background_thread(_probe, name=f'tls-connect-probe-{daddr}-{dport}')
        if not started:
            # _probe's finally never ran, so undo the in-flight marker here —
            # this endpoint will be retried on its next qualifying event.
            with self._probe_in_flight_lock:
                self._probe_in_flight.discard(endpoint_key)
            self.metrics.tls_port_probes_total.labels(status='skipped', node_name=self.metrics._node_name).inc()
            return
        logger.debug(
            f"Scheduled TLS outbound probe {daddr}:{dport} pid={pid} process={process_name}"
        )
