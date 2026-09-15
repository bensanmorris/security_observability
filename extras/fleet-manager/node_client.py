"""
node_client.py -- thin client for cert-analyzer's /control/* routes (see
agent/health.py and agent/control.py in the main tree).

Every call returns a plain dict with an "ok" flag rather than raising, so
the fan-out code in fleet_state.py can put a per-node outcome in the
response instead of failing the whole page because one node is
mid-upgrade. The distinct error strings are what the UI shows in a node's
control badge, so they are deliberately short and stable.
"""
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

DEFAULT_TIMEOUT = 5.0


class NodeTls:
    """
    TLS material for talking to nodes whose [control] listener is HTTPS.
    `ca` verifies the node's server certificate (hostname/IP checked
    against its SAN unless verify_hostname=False); `client_cert`/`client_key`
    is the fleet manager's own identity for mutual TLS. One SSLContext is
    built up front and shared -- loading PEMs per request would be waste.
    """

    def __init__(self, ca: Optional[str] = None, client_cert: Optional[str] = None,
                 client_key: Optional[str] = None, verify_hostname: bool = True):
        self.ca = ca or None
        self.client_cert = client_cert or None
        self.client_key = client_key or None
        self.verify_hostname = verify_hostname
        ctx = ssl.create_default_context(cafile=self.ca) if self.ca else ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not verify_hostname:
            ctx.check_hostname = False
        if self.client_cert:
            ctx.load_cert_chain(self.client_cert, self.client_key)
        self.context = ctx

    @property
    def configured(self) -> bool:
        return bool(self.ca or self.client_cert)

# Error codes surfaced to the UI. "unreachable" covers everything that
# never got an HTTP answer: no listener (the node's [control] is off, or
# the package was built without it), a firewall, a loopback listener with
# no tunnel, a TLS failure -- fleet_state.py tells those apart with the
# node's cert_analyzer_config_info{fleet_control=...} from Prometheus.
# "unauthorized" is a 401 (token mismatch); "forbidden" is a 403 (our
# address isn't in the node's allowed_sources, or our client certificate's
# CN isn't in either of its lists); "not_control" is a bodiless 404, i.e.
# something answered but it has no /control routes (the health port?).
ERR_UNREACHABLE = "unreachable"
ERR_UNAUTHORIZED = "unauthorized"
ERR_FORBIDDEN = "forbidden"
ERR_NOT_CONTROL = "not_control"
ERR_BAD_RESPONSE = "bad_response"


class NodeClient:
    def __init__(self, base_url: str, token: str, timeout: float = DEFAULT_TIMEOUT,
                 tls: Optional[NodeTls] = None):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._tls = tls

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method)
        if self._token:
            req.add_header("Authorization", f"Bearer {self._token}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        context = self._tls.context if (self._tls and self.base_url.startswith("https://")) else None
        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=context) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw = e.read()
            status = e.code
        except ssl.SSLError as e:
            # Wrong CA, node cert without a matching SAN, our client cert
            # refused: all "unreachable" from the operator's point of view,
            # but the detail says which.
            return {"ok": False, "error": ERR_UNREACHABLE, "detail": f"tls: {e}"}
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as e:
            return {"ok": False, "error": ERR_UNREACHABLE, "detail": str(e)}
        if status == 401:
            return {"ok": False, "error": ERR_UNAUTHORIZED, "status": 401}
        if status == 403 and not raw:
            # The control listener's refusals are bodiless; a 403 *with* a
            # JSON body would be the fleet manager's own, never a node's.
            return {"ok": False, "error": ERR_FORBIDDEN, "status": 403}
        try:
            payload = json.loads(raw) if raw else {}
        except ValueError:
            return {"ok": False, "error": ERR_BAD_RESPONSE, "status": status}
        if not isinstance(payload, dict):
            return {"ok": False, "error": ERR_BAD_RESPONSE, "status": status}
        if status == 404 and "error" not in payload:
            # A 404 for an unknown policy carries a JSON error; a bodiless one
            # means this URL isn't a control listener at all.
            return {"ok": False, "error": ERR_NOT_CONTROL, "status": 404}
        payload["ok"] = 200 <= status < 300
        payload["status"] = status
        return payload

    def info(self) -> dict:
        return self._request("GET", "/control/info")

    def policies(self) -> dict:
        return self._request("GET", "/control/policies")

    def set_policy(self, name: str, namespace: str, enabled: bool) -> dict:
        path = "/control/policies/" + urllib.parse.quote(name, safe="")
        if namespace:
            path += "?" + urllib.parse.urlencode({"namespace": namespace})
        return self._request("PUT", path, {"enabled": bool(enabled)})
