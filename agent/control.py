"""
Fleet-control support for CertificateAnalyzer: the persisted *desired*
enabled/disabled state of Tetragon tracing policies, and the gRPC call that
applies it.

Why desired state has to live here at all: a Tetragon enable/disable RPC
is in-memory only. On the next Tetragon restart, bare-metal installs reload
every policy in /etc/tetragon/tetragon.tp.d as enabled, and k8s installs
reload the TracingPolicy CR the same way -- so a policy an operator switched
off through the fleet manager silently comes back on. cert-analyzer already
sits next to Tetragon on every node with a gRPC channel and a periodic
policy check, so it records what the operator asked for and re-applies it
whenever Tetragon's reported state drifts (see
_TetragonMonitorMixin._reconcile_policy_state).

Only ever touches policies Tetragon currently lists. Adding/deleting
policies stays with the RPM / Helm chart; this module cannot load YAML.
"""
import json
import logging
import os
import re
import threading
import time
from typing import Dict, Optional

import grpc

from tetragon import sensors_pb2

# Logger name is hardcoded (not __name__) so log records keep reporting under
# "agent.analyzer" like the other mixin modules -- see java_fips.py.
logger = logging.getLogger("agent.analyzer")

# Tetragon policy names are Kubernetes object names on k8s and whatever the
# YAML's metadata.name says on bare metal (the RHEL8 notes in
# tetragon-policies/ show they can legitimately contain dots). Permissive on
# the character set, strict on length, and never starts with a separator so
# a name can't be used to walk a path or smuggle whitespace into a log line.
POLICY_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$')

# Shortest shared secret [control] will accept. A 16-byte token_urlsafe is
# 22 chars; the documented generator produces 43. Anything shorter is almost
# certainly a placeholder that was never replaced.
MIN_CONTROL_TOKEN_LENGTH = 16

# Enabled/disabled are the only states a configure call is meaningful for.
# load_error/error are Tetragon's problem, loading/unloading are transient,
# unknown means the bindings and daemon disagree about the enum.
_ENABLED_STATE = 1
_DISABLED_STATE = 2


def policy_key(name: str, namespace: str = '') -> str:
    """Stable dict key for a (name, namespace) pair; namespace is '' on hosts."""
    return f"{namespace}/{name}" if namespace else name


class PolicyDesiredState:
    """
    Thread-safe map of policy -> desired enabled flag, persisted as JSON.

    The file is written atomically (temp + os.replace) so a crash mid-write
    can never leave a half-written file that the next start then refuses to
    parse and silently forgets every recorded decision from. A missing or
    unreadable file is an empty state, not an error: an operator who has
    never toggled anything has no desired state, and Tetragon's own defaults
    are the answer.
    """

    def __init__(self, path: Optional[str]):
        self.path = path
        self._lock = threading.Lock()
        self._policies: Dict[str, dict] = {}
        self._writable = path is not None
        self._load()

    def _load(self) -> None:
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, 'r') as f:
                data = json.load(f)
        except (OSError, ValueError) as e:
            logger.error(
                f"Could not read policy desired-state file {self.path}: {e} -- "
                f"starting with no recorded policy decisions"
            )
            return
        policies = data.get('policies') if isinstance(data, dict) else None
        if not isinstance(policies, dict):
            logger.error(
                f"Policy desired-state file {self.path} has an unexpected shape -- "
                f"starting with no recorded policy decisions"
            )
            return
        loaded: Dict[str, dict] = {}
        for key, entry in policies.items():
            if not isinstance(entry, dict) or not isinstance(entry.get('enabled'), bool):
                logger.warning(f"Ignoring malformed desired-state entry for policy {key!r}")
                continue
            loaded[key] = {
                'name': str(entry.get('name', key)),
                'namespace': str(entry.get('namespace', '')),
                'enabled': entry['enabled'],
                'updated_at': str(entry.get('updated_at', '')),
            }
        self._policies = loaded
        logger.info(f"Loaded {len(loaded)} recorded policy decision(s) from {self.path}")

    def _save_locked(self) -> None:
        """Persist under self._lock. Failures are logged, never raised: the
        in-memory decision still applies for this process's lifetime, and a
        read-only /var/lib is an operator problem to see in the journal, not
        a reason to refuse the toggle."""
        if not self.path or not self._writable:
            return
        tmp = f"{self.path}.tmp"
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(tmp, 'w') as f:
                json.dump({'version': 1, 'policies': self._policies}, f, indent=2, sort_keys=True)
                f.write('\n')
            os.replace(tmp, self.path)
        except OSError as e:
            logger.error(
                f"Could not persist policy desired-state to {self.path}: {e} -- "
                f"the decision applies until restart only"
            )
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def set(self, name: str, namespace: str, enabled: bool) -> dict:
        with self._lock:
            entry = {
                'name': name,
                'namespace': namespace,
                'enabled': enabled,
                'updated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            }
            self._policies[policy_key(name, namespace)] = entry
            self._save_locked()
            return dict(entry)

    def get(self, name: str, namespace: str = '') -> Optional[dict]:
        with self._lock:
            entry = self._policies.get(policy_key(name, namespace))
            return dict(entry) if entry else None

    def all(self) -> Dict[str, dict]:
        with self._lock:
            return {k: dict(v) for k, v in self._policies.items()}


def set_tracing_policy_enabled(stub, name: str, namespace: str, enabled: bool,
                               timeout: float = 10.0) -> None:
    """
    Enable or disable one loaded tracing policy through Tetragon's gRPC API.

    Prefers ConfigureTracingPolicy (the current API) and falls back to the
    Enable/DisableTracingPolicy pair only when the daemon answers
    UNIMPLEMENTED, i.e. predates it (Tetragon 1.0-1.2, which this project
    has shipped against). The fallback is *not* tried on any other error:
    on Tetragon 1.7 the deprecated pair is gated behind
    --enable-deprecated-tracingpolicy-grpc and answers UNKNOWN with a
    "deprecated" message, so it can never rescue a Configure failure there.
    Tetragon also rejects a no-op transition ("policy X is not disabled");
    callers check the observed state first rather than relying on this
    being idempotent. Raises grpc.RpcError on failure -- callers decide
    whether that's a 502 or a warning.
    """
    if hasattr(sensors_pb2, 'ConfigureTracingPolicyRequest'):
        try:
            stub.ConfigureTracingPolicy(
                sensors_pb2.ConfigureTracingPolicyRequest(
                    name=name, namespace=namespace, enable=enabled,
                ),
                timeout=timeout,
            )
            return
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.UNIMPLEMENTED:
                raise
            logger.debug("ConfigureTracingPolicy unimplemented by this Tetragon; using Enable/Disable")
    if enabled:
        stub.EnableTracingPolicy(
            sensors_pb2.EnableTracingPolicyRequest(name=name, namespace=namespace),
            timeout=timeout,
        )
    else:
        stub.DisableTracingPolicy(
            sensors_pb2.DisableTracingPolicyRequest(name=name, namespace=namespace),
            timeout=timeout,
        )


def observed_matches_desired(state: int, enabled: bool) -> Optional[bool]:
    """
    True/False if Tetragon's reported state is a settled enabled/disabled
    that does or doesn't match the desired flag; None if the policy is in
    a state (error, loading, ...) where a configure call is meaningless.
    """
    if state == _ENABLED_STATE:
        return enabled is True
    if state == _DISABLED_STATE:
        return enabled is False
    return None
