#!/usr/bin/python3.11
"""Starts the AWS demo's k8s node on demand and reports its state.

Runs on the main demo instance behind nginx. Demo infrastructure, not product
code: it lives here rather than in the test console so AWS calls never ship in
an RPM. Stdlib only, because the main box has neither boto3 nor the AWS CLI.

It can only ever START the node. Stopping is the node's own job (see
k8s-demo-autostop.timer), so a session still ends if this service or the whole
main box is down. Each start therefore costs at most one session, and
STARTS_PER_DAY bounds what a public button can spend.
"""
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

logger = logging.getLogger("k8s-demo-control")

IMDS = "http://169.254.169.254"
EC2_API_VERSION = "2016-11-15"
STATUS_CACHE_SECONDS = 3
# Normally a post-boot event proves Tetragon -> analyzer works. This is the
# fallback so a quiet node can't stay "starting" for its whole session.
READY_GRACE_SECONDS = 180
# DescribeInstances can still say "stopped" just after a successful start.
START_SETTLE_SECONDS = 30
LAST_EVENT_RE = re.compile(r"^cert_analyzer_last_event_timestamp(?:\{[^}]*\})? (\S+)$", re.M)


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_authorization(method, host, path, query, headers, body, access_key, secret_key,
                        region, service, amz_date):
    """Return the SigV4 Authorization header value. `headers` must include host and x-amz-date."""
    names = sorted(name.lower() for name in headers)
    lowered = {name.lower(): " ".join(str(value).split()) for name, value in headers.items()}
    canonical_headers = "".join(f"{name}:{lowered[name]}\n" for name in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join([
        method, path, query, canonical_headers, signed_headers,
        hashlib.sha256(body).hexdigest(),
    ])
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{secret_key}".encode(), date), region), service),
                "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    return (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")


class Ec2Client:
    """The two EC2 calls this service needs, using the instance role via IMDSv2."""

    def __init__(self, region, instance_id):
        self.region = region
        self.instance_id = instance_id
        self._credentials = None
        self._credentials_expire = 0.0

    def _imds(self, path, token):
        request = urllib.request.Request(f"{IMDS}{path}",
                                         headers={"X-aws-ec2-metadata-token": token})
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.read().decode()

    def _load_credentials(self):
        if self._credentials and time.time() < self._credentials_expire:
            return self._credentials
        request = urllib.request.Request(
            f"{IMDS}/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"})
        with urllib.request.urlopen(request, timeout=3) as response:
            token = response.read().decode()
        base = "/latest/meta-data/iam/security-credentials/"
        role = self._imds(base, token).strip().splitlines()[0]
        credentials = json.loads(self._imds(f"{base}{role}", token))
        expires = datetime.datetime.fromisoformat(credentials["Expiration"].replace("Z", "+00:00"))
        self._credentials = credentials
        self._credentials_expire = expires.timestamp() - 300
        return credentials

    def _call(self, action, params):
        credentials = self._load_credentials()
        host = f"ec2.{self.region}.amazonaws.com"
        body = urllib.parse.urlencode({"Action": action, "Version": EC2_API_VERSION,
                                       **params}).encode()
        amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "Host": host,
            "X-Amz-Date": amz_date,
            "X-Amz-Security-Token": credentials["Token"],
        }
        headers["Authorization"] = sigv4_authorization(
            "POST", host, "/", "", headers, body, credentials["AccessKeyId"],
            credentials["SecretAccessKey"], self.region, "ec2", amz_date)
        request = urllib.request.Request(f"https://{host}/", data=body, headers=headers,
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return ET.fromstring(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:300]
            raise RuntimeError(f"{action} failed: HTTP {error.code}: {detail}") from error

    def describe(self):
        """Return (state name, launch time as epoch seconds)."""
        root = self._call("DescribeInstances", {"InstanceId.1": self.instance_id})
        return parse_describe(root)

    def start(self):
        self._call("StartInstances", {"InstanceId.1": self.instance_id})


def parse_describe(root):
    state = launch = None
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag == "launchTime" and launch is None:
            launch = element.text
        elif tag == "instanceState" and state is None:
            for child in element:
                if child.tag.rsplit("}", 1)[-1] == "name":
                    state = child.text
    if state is None or launch is None:
        raise RuntimeError("DescribeInstances returned no matching instance")
    return state, datetime.datetime.fromisoformat(launch.replace("Z", "+00:00")).timestamp()


class StartQuota:
    """Starts per UTC day, kept on disk so restarting the service can't reset it."""

    def __init__(self, path, limit, clock=time.time):
        self.path = Path(path)
        self.limit = limit
        self.clock = clock

    def _today(self):
        return datetime.datetime.fromtimestamp(self.clock(), datetime.timezone.utc).strftime("%Y-%m-%d")

    def used(self):
        try:
            data = json.loads(self.path.read_text())
            return int(data["starts"]) if data["day"] == self._today() else 0
        except FileNotFoundError:
            return 0
        except (ValueError, KeyError, TypeError):
            # Fail closed: this file is the only thing bounding the spend.
            logger.error("unreadable quota file %s, refusing starts", self.path)
            return self.limit

    def record(self):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"day": self._today(), "starts": self.used() + 1}))
        temporary.replace(self.path)


def http_get(url):
    """Return (status, body), or (0, "") when the node isn't answering."""
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status, response.read(4_000_000).decode(errors="replace")
    except (OSError, urllib.error.URLError):
        return 0, ""


class Controller:
    def __init__(self, ec2, quota, console_probe_url, metrics_url, public_console_url,
                 session_minutes, clock=time.time, fetch=http_get):
        self.ec2 = ec2
        self.quota = quota
        self.console_probe_url = console_probe_url
        self.metrics_url = metrics_url
        self.public_console_url = public_console_url
        self.session_seconds = session_minutes * 60
        self.clock = clock
        self.fetch = fetch
        self._lock = threading.Lock()
        self._cached = None
        self._cached_at = 0.0
        self._started_at = None

    def _settling(self):
        return self._started_at is not None and \
            self.clock() - self._started_at < START_SETTLE_SECONDS

    def _node_ready(self, launch):
        if self.fetch(self.console_probe_url)[0] != 200:
            return False
        if self.clock() - launch >= READY_GRACE_SECONDS:
            return True
        status, metrics = self.fetch(self.metrics_url)
        match = LAST_EVENT_RE.search(metrics) if status == 200 else None
        return bool(match) and float(match.group(1)) >= launch

    def _compute(self):
        state, launch = self.ec2.describe()
        used = self.quota.used()
        phase = {"stopped": "off", "pending": "starting", "stopping": "stopping",
                 "shutting-down": "stopping"}.get(state, "unknown")
        if state == "stopped" and self._settling():
            phase = "starting"
        if state == "running":
            phase = "ready" if self._node_ready(launch) else "starting"
        remaining = 0
        if phase in ("starting", "ready"):
            remaining = max(0, int(launch + self.session_seconds - self.clock()))
        return {
            "phase": phase,
            "remaining_seconds": remaining,
            "starts_used": used,
            "starts_limit": self.quota.limit,
            "can_start": phase == "off" and used < self.quota.limit,
            "session_minutes": self.session_seconds // 60,
            "console_url": self.public_console_url,
        }

    def status(self):
        with self._lock:
            if self._cached is None or self.clock() - self._cached_at >= STATUS_CACHE_SECONDS:
                self._cached = self._compute()
                self._cached_at = self.clock()
            return dict(self._cached)

    def start(self):
        """Return (HTTP status, status payload). A refusal never touches the instance."""
        with self._lock:
            state, _ = self.ec2.describe()
            if state != "stopped" or self._settling():
                code = 409
            elif self.quota.used() >= self.quota.limit:
                code = 429
            else:
                self.ec2.start()
                self.quota.record()
                self._started_at = self.clock()
                code = 202
            self._cached = None
        return code, self.status()


def make_handler(controller, panel_js):
    class Handler(BaseHTTPRequestHandler):
        server_version = "k8s-demo-control"
        sys_version = ""

        def log_message(self, format, *args):
            logger.debug(format, *args)

        def _send(self, code, body, content_type="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_failure(self):
            logger.exception("EC2 call failed")
            self._send(503, json.dumps({"phase": "unknown", "can_start": False}).encode())

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/k8s-demo/panel.js":
                self._send(200, panel_js, "text/javascript; charset=utf-8")
            elif path == "/k8s-demo/status":
                try:
                    self._send(200, json.dumps(controller.status()).encode())
                except Exception:
                    self._send_failure()
            else:
                self.send_error(404)

        def do_POST(self):
            if urllib.parse.urlparse(self.path).path != "/k8s-demo/start":
                self.send_error(404)
            elif self.headers.get("X-K8s-Demo") != "1":
                # Stops another site auto-submitting a cross-origin form at it.
                self.send_error(403)
            else:
                try:
                    code, payload = controller.start()
                except Exception:
                    self._send_failure()
                    return
                logger.info("start from %s: %d", self.headers.get("X-Real-IP", "?"), code)
                self._send(code, json.dumps(payload).encode())

    return Handler


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    env = os.environ
    private_ip = env["K8S_NODE_PRIVATE_IP"]
    state_dir = Path(env.get("STATE_DIRECTORY", "/var/lib/k8s-demo-control"))
    quota = StartQuota(state_dir / "quota.json", int(env.get("STARTS_PER_DAY", "4")))
    controller = Controller(
        Ec2Client(env["AWS_REGION"], env["K8S_NODE_INSTANCE_ID"]), quota,
        f"http://{private_ip}:30090/", f"http://{private_ip}:9090/metrics",
        env["K8S_PUBLIC_CONSOLE_URL"], int(env.get("SESSION_MINUTES", "60")))
    panel_js = (Path(__file__).resolve().parent / "panel.js").read_bytes()
    server = ThreadingHTTPServer(("127.0.0.1", int(env.get("PORT", "8096"))),
                                 make_handler(controller, panel_js))
    logger.info("listening on 127.0.0.1:%s", server.server_address[1])
    server.serve_forever()


if __name__ == "__main__":
    main()
