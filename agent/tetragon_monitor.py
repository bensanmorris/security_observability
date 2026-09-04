"""
Tetragon version/policy monitoring and process-metrics background threads for
CertificateAnalyzer.

Split out of agent/analyzer.py as part of the monolithic-analyzer file split --
see that module's docstring for the full list of mixins CertificateAnalyzer
composes. _TetragonMonitorMixin assumes the composing class provides the
instance state set up in CertificateAnalyzer.__init__ (self.metrics,
self._known_policy_labels).
"""
import logging
import os
import threading
import time
from typing import Dict, Set, Tuple

from tetragon import sensors_pb2

from .constants import _POLICY_STATE_NAMES

# Logger name is hardcoded (not __name__) so log records from this mixin keep
# reporting under "agent.analyzer" -- see the identical note in java_fips.py.
logger = logging.getLogger("agent.analyzer")


class _TetragonMonitorMixin:
    """
    Tetragon version/policy checks plus their periodic background-thread
    monitors, and the process-metrics refresh thread. Mixed into
    CertificateAnalyzer -- see module docstring.
    """

    @staticmethod
    def _int_env(name: str, default: int) -> int:
        """
        Read an integer env var, falling back to `default` (and logging a
        warning) on a missing or non-integer value, so a typo'd override
        (e.g. PROCESS_METRICS_INTERVAL=15s) degrades to the default instead
        of crashing analyzer startup with an unhandled ValueError.
        """
        raw = os.getenv(name)
        if raw is None:
            return default
        try:
            return int(raw)
        except ValueError:
            logger.warning(
                f"Invalid integer value {raw!r} for {name}, using default {default}"
            )
            return default

    def get_runtime_tetragon_version(self, stub) -> str:
        """
        Query the running Tetragon daemon for its version via GetVersion RPC.

        Returns the version string (e.g. 'v1.1.0') on success, or 'unknown'
        if the call fails or the version field is absent. Failures are logged
        as warnings and never propagate — a version mismatch should alert but
        must never prevent the analyzer from starting.
        """
        if not hasattr(sensors_pb2, 'GetVersionRequest'):
            logger.warning(
                "GetVersionRequest is not available in this version of the "
                "Tetragon protobuf bindings (requires > v1.1.0); skipping version check"
            )
            return 'unknown'
        try:
            response = stub.GetVersion(
                sensors_pb2.GetVersionRequest(),
                timeout=5.0,
            )
            version = getattr(response, 'version', '').strip()
            return version if version else 'unknown'
        except Exception as e:
            logger.warning(f"Could not retrieve runtime Tetragon version: {e}")
            return 'unknown'

    def check_tetragon_version(self, stub) -> None:
        """
        Compare the build-time and runtime Tetragon versions, update Prometheus
        metrics, and log a clear warning if they differ.

        Called once at startup after the gRPC channel is established.

        Reads TETRAGON_BUILD_VERSION off the agent.analyzer module (a deferred
        import to dodge the circular top-level import that would otherwise
        create) rather than importing it directly here: test_cert_analyzer.py
        monkeypatches it via agent.analyzer.TETRAGON_BUILD_VERSION, and that
        patch has no effect on a separate `from .constants import
        TETRAGON_BUILD_VERSION` binding in this file's own namespace.
        """
        from . import analyzer as _analyzer_module
        runtime_version = self.get_runtime_tetragon_version(stub)
        build_version   = _analyzer_module.TETRAGON_BUILD_VERSION

        self.metrics.tetragon_version_info.labels(node_name=self.metrics._node_name).info({
            'build_version':   build_version,
            'runtime_version': runtime_version,
        })

        versions_match = (
            build_version   != 'unknown'
            and runtime_version != 'unknown'
            and build_version   == runtime_version
        )
        self.metrics.tetragon_version_match.labels(node_name=self.metrics._node_name).set(1 if versions_match else 0)

        if build_version == 'unknown' or runtime_version == 'unknown':
            logger.warning(
                f"Tetragon version check incomplete — "
                f"build: {build_version}, runtime: {runtime_version}"
            )
        elif versions_match:
            logger.info(
                f"Tetragon version OK — build and runtime both at {build_version}"
            )
        else:
            logger.warning(
                f"⚠️  Tetragon version MISMATCH — "
                f"built against {build_version}, runtime is {runtime_version}. "
                f"Proto incompatibilities may cause silent failures. "
                f"Rebuild the cert-analyzer image against {runtime_version}."
            )

    def _start_version_monitor(self, stub) -> None:
        """
        Start a background daemon thread that periodically re-checks the
        runtime Tetragon version and updates Prometheus metrics.

        This detects Tetragon upgrades or downgrades that occur while the
        analyzer is running without requiring an analyzer restart.

        Interval is configurable via TETRAGON_VERSION_CHECK_INTERVAL env var
        (default: 300 seconds / 5 minutes).
        """
        interval = self._int_env('TETRAGON_VERSION_CHECK_INTERVAL', 300)

        def _monitor():
            while True:
                time.sleep(interval)
                try:
                    self.check_tetragon_version(stub)
                except Exception as e:
                    logger.warning(f"Version monitor error: {e}")

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.name = 'tetragon-version-monitor'
        thread.start()
        logger.info(f"Started Tetragon version monitor (interval: {interval}s)")

    def check_tetragon_policies(self, stub) -> None:
        """
        Query Tetragon for all tracing policies and update Prometheus metrics.

        Exposes two metrics:
          - tetragon_policy_info{name, namespace, state}=1  (presence per policy)
          - tetragon_policies_total{state}=N                (count per state)

        Stale series are removed when a policy is deleted or changes state,
        so the metrics always reflect the live policy table. Failures are
        logged as warnings and never propagate.
        """
        if not hasattr(sensors_pb2, 'ListTracingPoliciesRequest'):
            logger.warning(
                "ListTracingPoliciesRequest not available in Tetragon protobuf "
                "bindings; skipping policy check"
            )
            return
        try:
            response = stub.ListTracingPolicies(
                sensors_pb2.ListTracingPoliciesRequest(),
                timeout=5.0,
            )
        except Exception as e:
            logger.warning(f"Could not list Tetragon tracing policies: {e}")
            return

        new_labels: Set[Tuple[str, str, str, str]] = set()
        state_counts: Dict[str, int] = {}

        for policy in response.policies:
            state_str = _POLICY_STATE_NAMES.get(policy.state, 'unknown')
            ns = policy.namespace or ''
            key = (policy.name, ns, state_str, self.metrics._node_name)
            new_labels.add(key)
            state_counts[state_str] = state_counts.get(state_str, 0) + 1

        # Remove series for policies that were deleted or changed state
        for name, ns, state_str, node_name in self._known_policy_labels - new_labels:
            self.metrics.tetragon_policy_info.remove(name, ns, state_str, node_name)

        for name, ns, state_str, node_name in new_labels:
            self.metrics.tetragon_policy_info.labels(
                name=name, namespace=ns, state=state_str, node_name=node_name
            ).set(1)

        # Always emit a count for every known state so queries don't return no-data
        for state_str in _POLICY_STATE_NAMES.values():
            self.metrics.tetragon_policies_total.labels(state=state_str, node_name=self.metrics._node_name).set(
                state_counts.get(state_str, 0)
            )

        self._known_policy_labels = new_labels
        logger.debug(f"Tetragon policy states: {state_counts}")

    def _start_policy_monitor(self, stub) -> None:
        """
        Start a background daemon thread that periodically re-queries tracing
        policy state and updates Prometheus metrics.

        Interval is configurable via TETRAGON_POLICY_CHECK_INTERVAL env var
        (default: 60 seconds).
        """
        interval = self._int_env('TETRAGON_POLICY_CHECK_INTERVAL', 60)

        def _monitor():
            while True:
                time.sleep(interval)
                try:
                    self.check_tetragon_policies(stub)
                except Exception as e:
                    logger.warning(f"Policy monitor error: {e}")

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.name = 'tetragon-policy-monitor'
        thread.start()
        logger.info(f"Started Tetragon policy monitor (interval: {interval}s)")

    def _start_process_metrics_monitor(self) -> None:
        """
        Start a background daemon thread that periodically refreshes the
        process CPU/RSS gauges (cert_analyzer_process_cpu_seconds_total,
        cert_analyzer_process_rss_bytes, cert_analyzer_process_cpu_percent).

        RSS and cumulative CPU-seconds also update as a side-effect of
        cert-processing events (_update_cache_metrics), but relying on that
        alone leaves them frozen during quiet periods with no matching
        Tetragon events. The next event then dumps all the CPU/RSS change
        accumulated across the whole gap into a single sample — which
        Grafana's deriv()-based panels render as a large spike that never
        actually happened at that instant. A fixed timer keeps the gauges
        live regardless of event traffic, independent of any Tetragon
        connectivity (unlike the version/policy monitors, this doesn't need
        a stub).

        cert_analyzer_process_cpu_percent (sample_cpu_percent) is only ever
        sampled here, at this fixed cadence, never from the per-event path —
        see its docstring for why calling it more often would make it noisy
        rather than more accurate.

        Interval is configurable via PROCESS_METRICS_INTERVAL env var
        (default: 15 seconds, matching the default Prometheus scrape interval).
        """
        interval = self._int_env('PROCESS_METRICS_INTERVAL', 15)

        def _monitor():
            while True:
                time.sleep(interval)
                try:
                    self.metrics.update_process_metrics()
                    self.metrics.sample_cpu_percent()
                except Exception as e:
                    logger.warning(f"Process metrics monitor error: {e}")

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.name = 'process-metrics-monitor'
        thread.start()
        logger.info(f"Started process metrics monitor (interval: {interval}s)")
