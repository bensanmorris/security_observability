"""
New-certificate rate limiter and retry-queue pipeline for CertificateAnalyzer.

Split out of agent/analyzer.py as part of the monolithic-analyzer file split --
see that module's docstring for the full list of mixins CertificateAnalyzer
composes. _RateLimitRetryQueueMixin assumes the composing class provides the
instance state set up in CertificateAnalyzer.__init__ (self._rate_limit_log_lock,
self._rate_limit_dropped_since_log, self._rate_limit_last_log_time,
self.processed_paths, self.known_certs, self.kafka_publisher, self.metrics,
self._new_cert_rate_limiter, self._retry_queue/_retry_queue_lock/
_retry_queue_paths/_retry_queue_max_size, self._known_paths/_known_paths_lock)
and methods from its sibling mixins (self.parse_certificates,
self.extract_certificate_info, self._apply_pod_context,
self.log_certificate_status, self._snapshot_pod_context) and the core class
(self._update_cache_metrics).
"""
import logging
import threading
import time
from typing import List, NamedTuple, Optional

from .event_context import _PodContextSnapshot
from .models import CertificateInfo

# Logger name is hardcoded (not __name__) so log records from this mixin keep
# reporting under "agent.analyzer" -- see the identical note in java_fips.py.
logger = logging.getLogger("agent.analyzer")


class _TokenBucket:
    """
    Thread-safe token bucket, refilled continuously at `rate` tokens/sec up to
    a cap of `rate` tokens -- so up to a full second's worth of legitimate
    burst (e.g. many pods restarting at once and touching their certs) is
    never throttled, but sustained throughput above `rate`/sec is capped
    regardless of how fast events keep arriving. `rate <= 0` disables the
    limiter entirely (every acquire succeeds), for operators who want it off.
    """

    def __init__(self, rate: float):
        self._rate = max(rate, 0.0)
        self._tokens = self._rate
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        if self._rate <= 0:
            return True
        with self._lock:
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


class _RetryEntry(NamedTuple):
    """
    Captures everything needed to fully replay a rate-limited new-certificate
    file later, exactly as if the original event were being handled -- unlike
    periodic_scan's rediscovery path, this preserves the real triggering
    process/pod context instead of falling back to synthetic
    process="periodic_scan", pid=0 attribution.

    Stores a _PodContextSnapshot rather than the live Tetragon pod proto:
    entries can sit in the queue (up to retry_queue_max_size, unbounded time)
    long enough that the originating pid is almost certain to have been
    recycled by replay time, and there's no reason to keep a live gRPC
    message alive that long just to read a handful of strings out of it.
    """
    cert_path: str
    process_name: str
    pid: int
    namespace: str
    pod_context: Optional[_PodContextSnapshot]
    parent_process: str
    parent_pid: int
    node_name: str


class _RateLimitRetryQueueMixin:
    """
    New-certificate rate limiter and retry-queue pipeline: every fresh
    trigger of a never-before-seen certificate file (real-time Tetragon
    events, periodic_scan, and the large-file background-thread worker) goes
    through _analyze_and_finish_new_certificate_file so rate-limiting and
    retry-queueing apply uniformly regardless of source. Mixed into
    CertificateAnalyzer -- see module docstring.
    """

    def _log_rate_limited_new_cert(self, cert_path: str) -> None:
        """
        Log a rate-limit hit at most once every 10 seconds, with a count of
        how many were dropped in between -- logging every single throttled
        event would just move the flood from CPU cost to log-volume cost.
        """
        with self._rate_limit_log_lock:
            self._rate_limit_dropped_since_log += 1
            now = time.monotonic()
            if now - self._rate_limit_last_log_time < 10.0:
                return
            dropped = self._rate_limit_dropped_since_log
            self._rate_limit_dropped_since_log = 0
            self._rate_limit_last_log_time = now
        logger.warning(
            f"New-certificate analysis rate limit reached (most recently for {cert_path}) -- "
            f"{dropped} new-file event(s) skipped in the last ~10s. Tune via "
            f"[certificates] new_cert_events_per_second in cert-analyzer.conf or "
            f"NEW_CERT_EVENTS_PER_SECOND."
        )

    def analyze_certificate(
        self,
        cert_path: str,
        process: str,
        pid: int,
        namespace: str = ""
    ) -> List[CertificateInfo]:
        """
        Analyze a certificate file and return list of CertificateInfo (supports
        multi-cert files). Pure parse-and-extract -- callers that are handling
        a never-before-seen path should go through
        _try_process_new_certificate_file()/_analyze_and_finish_new_certificate_file()
        instead of calling this directly, so the new-cert rate limiter and
        retry queue apply consistently.
        """

        try:
            certs = self.parse_certificates(cert_path)
        except Exception as e:
            logger.error(f"Unexpected error parsing certificates from {cert_path}: {e}",
                         exc_info=True)
            self.metrics.cert_analysis_errors.labels(error_type='parse_error', node_name=self.metrics._node_name).inc()
            return []

        if not certs:
            return []

        cert_infos = []
        for idx, cert in enumerate(certs):
            try:
                cert_info = self.extract_certificate_info(
                    cert, cert_path, process, pid, namespace, cert_index=idx
                )
                if cert_info is None:
                    # extract_certificate_info already logged and incremented
                    # the error metric — skip this cert and continue with others
                    continue
                cert_infos.append(cert_info)
                self.metrics.cert_events_total.labels(event_type='analysis', status='success', node_name=self.metrics._node_name).inc()
            except Exception as e:
                logger.error(f"Error extracting certificate info from {cert_path} (cert {idx}): {e}")
                self.metrics.cert_events_total.labels(event_type='analysis', status='failed', node_name=self.metrics._node_name).inc()
                self.metrics.cert_analysis_errors.labels(error_type='extraction_error', node_name=self.metrics._node_name).inc()

        self.processed_paths.add(cert_path)
        self._update_cache_metrics()
        return cert_infos

    def _finish_new_certificate_file(
        self,
        cert_infos: List[CertificateInfo],
        tetragon_pod,
        parent_process: str,
        parent_pid: int,
        node_name: str,
    ) -> None:
        """Apply pod/event context, update metrics, log, cache, and publish for a freshly-parsed file."""
        # update_certificate_metrics() writes ~7 Prometheus series per cert.
        # A bundle file (e.g. a system CA trust store) can hold hundreds of
        # certs, so tracking every one individually turns a single file event
        # into thousands of new series in one burst — this is what drove
        # cert-analyzer's cardinality/memory spike and hang on 2026-07-03.
        # Beyond large_file_metrics_cap (deliberately separate from
        # _large_file_cert_threshold, which only controls background-thread
        # parsing — conflating the two would mean raising the metrics cap to
        # cover a realistic bundle also disables the background-thread path
        # for that same bundle), only the first `metrics_cap` certs get full
        # per-cert metrics/logging; the rest are still cached — so known-file
        # lookups and cache size stay accurate — but summarized in one log
        # line instead of fanning out more series.
        metrics_cap = self._large_file_metrics_cap
        is_bundle = len(cert_infos) > metrics_cap
        skipped_self_signed = 0
        skipped_fips_noncompliant = 0

        for i, cert_info in enumerate(cert_infos):
            try:
                self._apply_pod_context(cert_info, tetragon_pod)
                cert_info.node_name      = node_name
                cert_info.parent_process = parent_process
                cert_info.parent_pid     = parent_pid

                if not is_bundle or i < metrics_cap:
                    self.metrics.update_certificate_metrics(cert_info)
                    self.log_certificate_status(cert_info)
                else:
                    if cert_info.is_self_signed:
                        skipped_self_signed += 1
                    if cert_info.fips_violations:
                        skipped_fips_noncompliant += 1

                self.known_certs[cert_info.unique_key] = cert_info

                if self.kafka_publisher is not None:
                    self.kafka_publisher.publish(cert_info)
            except Exception as e:
                # One bad cert (e.g. an unexpected label value) must not abort
                # the rest of the file — each cert is otherwise independent.
                logger.error(
                    f"Error finishing certificate {cert_info.cert_index} in "
                    f"{cert_info.path}: {e}", exc_info=True
                )
                self.metrics.cert_events_total.labels(
                    event_type='processing', status='error', node_name=self.metrics._node_name
                ).inc()
                self.metrics.cert_analysis_errors.labels(error_type='finish_error', node_name=self.metrics._node_name).inc()

        if is_bundle:
            remaining = len(cert_infos) - metrics_cap
            logger.info(
                f"{cert_infos[0].path}: bundle of {len(cert_infos)} certs — "
                f"tracked metrics/logging for the first {metrics_cap}; "
                f"{remaining} more cached but not individually tracked "
                f"({skipped_self_signed} self-signed, {skipped_fips_noncompliant} "
                f"FIPS non-compliant among them, not individually alertable)"
            )

        self._update_cache_metrics()

    def _try_process_new_certificate_file(
        self,
        cert_path: str,
        process_name: str,
        pid: int,
        namespace: str,
        tetragon_pod,
        parent_process: str,
        parent_pid: int,
        node_name: str,
    ) -> Optional[List[CertificateInfo]]:
        """
        Attempt to fully process a never-before-seen certificate file, gated
        by the new-cert rate limiter. Returns None if no token was available
        (throttled); otherwise returns the list of CertificateInfo found
        (possibly empty, if the file turned out to contain no valid certs --
        that's not a throttling outcome). Callers decide what a None result
        means for them: a fresh trigger (see
        _analyze_and_finish_new_certificate_file) queues the file for retry;
        the retry-queue drainer just leaves its entry where it is and tries
        again later.
        """
        if not self._new_cert_rate_limiter.try_acquire():
            return None

        cert_infos = self.analyze_certificate(cert_path, process_name, pid, namespace)
        if cert_infos:
            logger.info(f"Found {len(cert_infos)} certificate(s) in {cert_path}")
            self._finish_new_certificate_file(
                cert_infos, tetragon_pod, parent_process, parent_pid, node_name
            )
        return cert_infos

    def _analyze_and_finish_new_certificate_file(
        self,
        cert_path: str,
        process_name: str,
        pid: int,
        namespace: str,
        tetragon_pod,
        parent_process: str,
        parent_pid: int,
        node_name: str,
    ) -> List[CertificateInfo]:
        """
        Entry point for every *fresh* trigger of a never-before-seen
        certificate file -- real-time Tetragon events, periodic_scan, and the
        large-file background-thread worker all call this instead of
        analyze_certificate()+_finish_new_certificate_file() directly, so
        rate-limiting and retry-queueing apply uniformly regardless of
        source. A throttled file is queued for replay (see
        _enqueue_rate_limited_retry) rather than being dropped; this returns
        [] for that case too, since nothing was found *in this call* --
        periodic_scan's cert_count tally relies on that.
        """
        cert_infos = self._try_process_new_certificate_file(
            cert_path, process_name, pid, namespace,
            tetragon_pod, parent_process, parent_pid, node_name,
        )
        if cert_infos is not None:
            return cert_infos

        self._log_rate_limited_new_cert(cert_path)
        self.metrics.cert_analysis_errors.labels(error_type='rate_limited', node_name=self.metrics._node_name).inc()
        self._enqueue_rate_limited_retry(
            cert_path, process_name, pid, namespace,
            tetragon_pod, parent_process, parent_pid, node_name,
        )
        return []

    def _enqueue_rate_limited_retry(
        self,
        cert_path: str,
        process_name: str,
        pid: int,
        namespace: str,
        tetragon_pod,
        parent_process: str,
        parent_pid: int,
        node_name: str,
    ) -> None:
        """
        Queue a rate-limited new-certificate file for replay by the
        retry-queue drainer thread once capacity frees up. Bounded FIFO --
        at capacity, the oldest entry is dropped to make room, so this can't
        become a second unbounded memory sink for the same abuse the rate
        limiter itself defends against. De-duped on cert_path so a file that
        keeps getting touched while already queued doesn't pile up repeat
        entries.
        """
        pod_context = self._snapshot_pod_context(tetragon_pod)
        with self._retry_queue_lock:
            if cert_path in self._retry_queue_paths:
                return
            if len(self._retry_queue) >= self._retry_queue_max_size:
                dropped = self._retry_queue.popleft()
                self._retry_queue_paths.discard(dropped.cert_path)
                self.metrics.cert_analysis_errors.labels(error_type='retry_queue_dropped', node_name=self.metrics._node_name).inc()
                logger.warning(
                    f"Rate-limit retry queue full ({self._retry_queue_max_size}) -- "
                    f"dropped oldest queued file {dropped.cert_path} to make room for {cert_path}"
                )
            self._retry_queue.append(_RetryEntry(
                cert_path, process_name, pid, namespace,
                pod_context, parent_process, parent_pid, node_name,
            ))
            self._retry_queue_paths.add(cert_path)
            depth = len(self._retry_queue)
        self.metrics.retry_queue_depth.labels(node_name=self.metrics._node_name).set(depth)

    def _start_retry_queue_drainer(self) -> None:
        """
        Start a background daemon thread that replays rate-limited
        new-certificate files from the retry queue as capacity frees up.

        Shares _new_cert_rate_limiter with every other trigger path rather
        than having its own budget, so replays and fresh arrivals compete
        for the same fixed throughput instead of the queue draining at an
        unbounded rate alongside live traffic.
        """
        def _drain():
            while True:
                with self._retry_queue_lock:
                    entry = self._retry_queue[0] if self._retry_queue else None
                if entry is None:
                    time.sleep(1.0)
                    continue

                # The path may have already been fully processed by an
                # unrelated event (a fresh Tetragon re-access, or
                # periodic_scan finding it under scan_paths) since it was
                # queued -- drop it without spending a token on a no-op
                # replay.
                with self._known_paths_lock:
                    already_known = entry.cert_path in self._known_paths
                if already_known:
                    with self._retry_queue_lock:
                        if self._retry_queue and self._retry_queue[0] == entry:
                            self._retry_queue.popleft()
                            self._retry_queue_paths.discard(entry.cert_path)
                            self.metrics.retry_queue_depth.labels(
                                node_name=self.metrics._node_name
                            ).set(len(self._retry_queue))
                    continue

                try:
                    result = self._try_process_new_certificate_file(
                        entry.cert_path, entry.process_name, entry.pid, entry.namespace,
                        entry.pod_context, entry.parent_process, entry.parent_pid, entry.node_name,
                    )
                except Exception as e:
                    logger.error(f"Error replaying queued certificate file {entry.cert_path}: {e}",
                                 exc_info=True)
                    result = []  # don't retry an entry that itself errors indefinitely

                if result is None:
                    time.sleep(0.1)  # no token yet -- back off briefly rather than busy-spin
                    continue

                with self._retry_queue_lock:
                    if self._retry_queue and self._retry_queue[0] == entry:
                        self._retry_queue.popleft()
                        self._retry_queue_paths.discard(entry.cert_path)
                        depth = len(self._retry_queue)
                    else:
                        depth = len(self._retry_queue)
                self.metrics.retry_queue_depth.labels(node_name=self.metrics._node_name).set(depth)
                logger.info(f"Replayed rate-limited certificate file {entry.cert_path} from retry queue")

        thread = threading.Thread(target=_drain, daemon=True)
        thread.name = 'rate-limit-retry-drainer'
        thread.start()
        logger.info(f"Started rate-limit retry queue drainer (max size: {self._retry_queue_max_size})")
