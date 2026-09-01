"""
Optional synthetic end-to-end canary: periodically drives every (or an
allow-listed subset of) use case exposed by an external test-server's HTTP
API, and exposes pass/fail as Prometheus gauges.

Unlike periodic_scan (which only re-discovers certs already on disk), this
proves the *whole* pipeline is alive end-to-end: Tetragon kprobe/uprobe ->
this analyzer's gRPC consumer -> cert parsing -> (optionally) Kafka -- on a
schedule, independent of whether any real workload happens to be touching
certificates right now.

Degrades silently (never started) when [system_test] test_server_url is
unset -- most deployments (real customer clusters) have no test-server, and
this feature must never be the thing that makes those installs noisy. See
[[project_system_test_design]] in memory for the design discussion.
"""
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Optional

from prometheus_client import Counter, Gauge

from .constants import _NODE_NAME

logger = logging.getLogger(__name__)

_REQUEST_TIMEOUT_SECONDS = 15
# Spread requests out across a poll pass rather than firing all use cases at
# once -- each one already generates real Tetragon events and (if enabled) a
# real Kafka publish, so a synchronized burst is exactly the kind of load
# spike this canary shouldn't itself be causing.
_USE_CASE_STAGGER_SECONDS = 1.0

systemtest_usecase_up = Gauge(
    'systemtest_usecase_up',
    '1 if the last system-test run of this use case succeeded, 0 if it failed',
    ['node_name', 'usecase'],
)

systemtest_usecase_last_run_timestamp_seconds = Gauge(
    'systemtest_usecase_last_run_timestamp_seconds',
    'Unix timestamp of the last system-test run of this use case',
    ['node_name', 'usecase'],
)

systemtest_usecase_duration_seconds = Gauge(
    'systemtest_usecase_duration_seconds',
    'Duration of the last system-test run of this use case, in seconds',
    ['node_name', 'usecase'],
)

systemtest_usecase_run_total = Counter(
    'systemtest_usecase_run_total',
    'Total number of system-test runs of this use case, by result',
    ['node_name', 'usecase', 'result'],
)

systemtest_all_passing = Gauge(
    'systemtest_all_passing',
    '1 if every use case passed its last run, 0 if any failed -- pipeline-health summary',
    ['node_name'],
)

systemtest_available = Gauge(
    'systemtest_available',
    '1 if the configured test-server was reachable on the last poll, 0 otherwise',
    ['node_name'],
)


def _fetch_use_case_ids(base_url: str, timeout: float) -> list:
    with urllib.request.urlopen(f"{base_url}/api/use-cases", timeout=timeout) as resp:
        payload = json.loads(resp.read())
    return [uc["id"] for uc in payload]


def _call_run_use_case(base_url: str, use_case_id: str, timeout: float):
    """
    POSTs an empty params body (every use case runs with its documented
    defaults) to /api/run/<id>. Returns (ok, detail) -- never raises, since
    the caller needs a result either way to update the Prometheus gauges.
    """
    req = urllib.request.Request(
        f"{base_url}/api/run/{use_case_id}",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read())
            return bool(body.get("ok")), body.get("detail", "")
    except urllib.error.HTTPError as e:
        # The test-server always sends a JSON body on its 500s too (see
        # server.py's _run_use_case) -- prefer that over the bare HTTP status.
        try:
            body = json.loads(e.read())
            return False, body.get("detail", str(e))
        except Exception:
            return False, str(e)
    except Exception as e:
        return False, str(e)


class SystemTestRunner:
    """Background poller -- one instance per analyzer process. See start()."""

    def __init__(
        self,
        base_url: str,
        interval_seconds: int = 300,
        use_case_allowlist: Optional[list] = None,
        request_timeout: float = _REQUEST_TIMEOUT_SECONDS,
    ):
        self._base_url = base_url.rstrip('/')
        self._interval_seconds = interval_seconds
        self._allowlist = set(use_case_allowlist) if use_case_allowlist else None
        self._timeout = request_timeout
        # use_case_id -> bool, last known result. Read back to compute
        # systemtest_all_passing and to log only on state transitions rather
        # than spamming the same failure every poll.
        self._last_result: dict = {}
        self._was_available: Optional[bool] = None

    def start(self) -> threading.Thread:
        thread = threading.Thread(target=self._loop, name='system-test', daemon=True)
        thread.start()
        return thread

    def _loop(self) -> None:
        while True:
            try:
                self._run_once()
            except Exception as e:
                # Must never take the whole daemon thread down -- a single
                # bad poll (e.g. a malformed /api/use-cases response) should
                # cost one interval, not silently end system testing for the
                # rest of the process's life with nothing in the logs to
                # explain why the gauges stopped moving.
                logger.error(f"system_test: unexpected error in poll loop: {e}", exc_info=True)
            time.sleep(self._interval_seconds)

    def _run_once(self) -> None:
        try:
            ids = _fetch_use_case_ids(self._base_url, self._timeout)
        except Exception as e:
            if self._was_available is not False:
                logger.warning(f"system_test: test-server at {self._base_url} unreachable: {e}")
            self._was_available = False
            systemtest_available.labels(node_name=_NODE_NAME).set(0)
            return

        if self._was_available is not True:
            logger.info(f"system_test: test-server at {self._base_url} reachable, {len(ids)} use case(s) registered")
        self._was_available = True
        systemtest_available.labels(node_name=_NODE_NAME).set(1)

        if self._allowlist:
            ids = [i for i in ids if i in self._allowlist]

        for use_case_id in ids:
            self._run_and_record(use_case_id)
            time.sleep(_USE_CASE_STAGGER_SECONDS)

        if ids:
            systemtest_all_passing.labels(node_name=_NODE_NAME).set(
                1 if all(self._last_result.get(i) for i in ids) else 0
            )

    def _run_and_record(self, use_case_id: str) -> None:
        started_at = time.time()
        ok, detail = _call_run_use_case(self._base_url, use_case_id, self._timeout)
        duration = time.time() - started_at

        if self._last_result.get(use_case_id) != ok:
            log = logger.info if ok else logger.warning
            log(f"system_test '{use_case_id}': {'ok' if ok else 'FAILED'} — {detail}")
        self._last_result[use_case_id] = ok

        labels = dict(node_name=_NODE_NAME, usecase=use_case_id)
        systemtest_usecase_up.labels(**labels).set(1 if ok else 0)
        systemtest_usecase_last_run_timestamp_seconds.labels(**labels).set(time.time())
        systemtest_usecase_duration_seconds.labels(**labels).set(duration)
        systemtest_usecase_run_total.labels(**labels, result='success' if ok else 'failure').inc()
