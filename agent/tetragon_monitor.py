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
# Fleet control is a separate package (cert-analyzer-control, or the
# -control image): the base cert-analyzer ships no agent/control.py.
# Everything below that needs it checks CONTROL_AVAILABLE; the policy check
# itself never depends on it.
try:
    from .control import (
        POLICY_NAME_RE, observed_matches_desired, policy_key, set_tracing_policy_enabled,
    )
    CONTROL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised by the base package
    CONTROL_AVAILABLE = False

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

    def check_tetragon_policies(self, stub, blocking: bool = True) -> None:
        """
        Query Tetragon for all tracing policies and update Prometheus metrics.

        Exposes two metrics:
          - tetragon_policy_info{name, namespace, state}=1  (presence per policy)
          - tetragon_policies_total{state}=N                (count per state)

        Stale series are removed when a policy is deleted or changes state,
        so the metrics always reflect the live policy table. Failures are
        logged as warnings and never propagate.

        Callers: the main thread at startup and on each event-stream
        reconnect, the policy monitor thread, and -- with [control] on --
        every HTTP worker handling a PUT. One run at a time, under
        _policy_check_lock (see analyzer.py).

        blocking=False makes the call opportunistic: if another thread is
        mid-check, return without doing anything rather than wait for it.
        The event-stream reconnect path uses this -- its purpose is "make
        sure recorded state gets re-applied promptly after Tetragon comes
        back", and a check already in flight on the monitor or a control
        PUT is doing exactly that, so the stream thread must not queue
        behind it (a monitor spinning on a zero interval would otherwise
        starve it -- seen in the reconnect tests, where time.sleep is a
        no-op).
        """
        if not self._policy_check_lock.acquire(blocking=blocking):
            logger.debug("Tetragon policy check already in progress on another thread; skipping")
            return
        try:
            self._check_tetragon_policies_locked(stub)
        finally:
            self._policy_check_lock.release()

    def _check_tetragon_policies_locked(self, stub) -> None:
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
        # Snapshot for the /control/policies route, so a read never has to
        # make its own gRPC round-trip on the HTTP thread.
        self._last_policy_list = [
            {'name': p.name, 'namespace': p.namespace or '',
             'state': _POLICY_STATE_NAMES.get(p.state, 'unknown'), 'state_code': p.state}
            for p in response.policies
        ]
        logger.debug(f"Tetragon policy states: {state_counts}")

        self._reconcile_policy_state(stub, response.policies)

    # ── Fleet control: desired policy state ──────────────────────────────────

    def _reconcile_policy_state(self, stub, policies) -> None:
        """
        Re-apply any recorded enable/disable decision that Tetragon's live
        state no longer reflects -- the step that makes a fleet-manager
        disable survive a Tetragon restart (see agent/control.py's module
        docstring for why the RPC alone doesn't).

        Runs on every policy check (startup, each event-stream reconnect,
        and the periodic monitor), so the longest a policy can be in the
        wrong state after Tetragon comes back is one monitor interval. Only
        policies Tetragon currently lists are touched; a recorded decision
        for a policy that's gone is left in the file and reported as stale
        by /control/policies rather than acted on. Policies in error or
        transitional states are skipped -- there is nothing a configure call
        can do for them.
        """
        state = getattr(self, '_policy_state', None)
        if state is None or not CONTROL_AVAILABLE:
            return
        desired = state.all()
        if not desired:
            return
        for policy in policies:
            entry = desired.get(policy_key(policy.name, policy.namespace or ''))
            if entry is None:
                continue
            matches = observed_matches_desired(policy.state, entry['enabled'])
            if matches is None or matches:
                continue
            want = 'enabled' if entry['enabled'] else 'disabled'
            try:
                set_tracing_policy_enabled(stub, policy.name, policy.namespace or '', entry['enabled'])
            except Exception as e:
                logger.warning(
                    f"Could not re-apply recorded state ({want}) to Tetragon policy "
                    f"{policy.name!r}: {e}"
                )
                continue
            self.metrics.policy_reconciliations_total.labels(
                policy=policy.name, node_name=self.metrics._node_name,
            ).inc()
            logger.info(
                f"Re-applied recorded state to Tetragon policy {policy.name!r}: "
                f"{_POLICY_STATE_NAMES.get(policy.state, 'unknown')} -> {want}"
            )

    def list_policies_for_control(self) -> dict:
        """
        Observed (last check) + desired (recorded) state of every policy, for
        GET /control/policies. Desired entries for policies Tetragon no
        longer lists are included with stale=True so the fleet manager can
        show them rather than have them vanish.
        """
        if not CONTROL_AVAILABLE:  # base package: no control server can call this, but be safe
            return {'policies': []}
        state = getattr(self, '_policy_state', None)
        desired = state.all() if state is not None else {}
        observed = list(getattr(self, '_last_policy_list', []) or [])
        seen = set()
        out = []
        for p in observed:
            key = policy_key(p['name'], p['namespace'])
            seen.add(key)
            entry = desired.get(key)
            matches = None
            if entry is not None:
                matches = observed_matches_desired(p['state_code'], entry['enabled'])
            out.append({
                'name': p['name'],
                'namespace': p['namespace'],
                'state': p['state'],
                'desired': entry['enabled'] if entry else None,
                'drift': (matches is False),
                'stale': False,
            })
        for key, entry in desired.items():
            if key in seen:
                continue
            out.append({
                'name': entry['name'],
                'namespace': entry['namespace'],
                'state': 'absent',
                'desired': entry['enabled'],
                'drift': False,
                'stale': True,
            })
        out.sort(key=lambda p: (p['namespace'], p['name']))
        return {'policies': out}

    def set_policy_enabled_for_control(self, name: str, namespace: str, enabled: bool) -> tuple:
        """
        The PUT /control/policies/{name} action. Returns (http_status, body).

        Order matters: the decision is recorded *before* the RPC so that if
        Tetragon is mid-restart the reconcile loop still applies it once
        Tetragon is back -- the operator's intent is not lost to a transient
        failure. Only policies Tetragon currently lists can be toggled; the
        list is refreshed first so a policy loaded seconds ago is accepted.
        """
        stub = getattr(self, '_tetragon_stub', None)
        state = getattr(self, '_policy_state', None)
        if not CONTROL_AVAILABLE or stub is None or state is None:
            return 503, {'error': 'tetragon_not_connected'}
        if not POLICY_NAME_RE.match(name) or (namespace and not POLICY_NAME_RE.match(namespace)):
            return 400, {'error': 'invalid_policy_name'}
        # Held across refresh -> record -> RPC -> refresh so the policy
        # monitor's reconcile can't see the new desired flag against the
        # old observed state mid-way and issue the same RPC first, which
        # would make Tetragon refuse ours and turn a successful toggle into
        # a 502. Two concurrent PUTs serialise here for the same reason.
        with self._policy_check_lock:
            return self._set_policy_enabled_locked(stub, state, name, namespace, enabled)

    def _set_policy_enabled_locked(self, stub, state, name: str, namespace: str, enabled: bool) -> tuple:
        try:
            self.check_tetragon_policies(stub)
        except Exception as e:  # never expected -- check_tetragon_policies swallows
            logger.warning(f"Policy refresh before toggle failed: {e}")
        known = {
            policy_key(p['name'], p['namespace']): p
            for p in (getattr(self, '_last_policy_list', []) or [])
        }
        current = known.get(policy_key(name, namespace))
        if current is None:
            return 404, {'error': 'unknown_policy', 'name': name, 'namespace': namespace}
        state.set(name, namespace, enabled)
        if observed_matches_desired(current['state_code'], enabled):
            # Tetragon rejects a no-op transition ("tracing policy X is not
            # disabled"), so an idempotent re-PUT of the current state is
            # answered here: the decision is still recorded so it survives
            # the next Tetragon restart, which is the part that matters.
            return 200, {'name': name, 'namespace': namespace,
                         'desired': enabled, 'state': current['state']}
        try:
            set_tracing_policy_enabled(stub, name, namespace, enabled)
        except Exception as e:
            logger.error(f"Tetragon refused {'enable' if enabled else 'disable'} of policy {name!r}: {e}")
            return 502, {'error': 'tetragon_rpc_failed', 'detail': str(e),
                         'name': name, 'namespace': namespace, 'desired': enabled}
        try:
            self.check_tetragon_policies(stub)
        except Exception as e:  # never expected -- check_tetragon_policies swallows
            logger.debug(f"Policy refresh after toggle failed: {e}")
        observed = next(
            (p for p in (getattr(self, '_last_policy_list', []) or [])
             if p['name'] == name and p['namespace'] == namespace),
            None,
        )
        return 200, {
            'name': name,
            'namespace': namespace,
            'desired': enabled,
            'state': observed['state'] if observed else 'unknown',
        }

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
