"""
audit.py -- append-only JSONL record of every state-changing action the
fleet manager performs, plus a mirror line in the journal.

One line per (node, policy) outcome, so a bulk toggle across ten nodes is
ten lines each carrying its own result. Written under a lock with an
fsync-free append: losing the last line in a power cut is acceptable, a
torn line mid-file is not, and append() of a single small write is atomic
on every filesystem this runs on.
"""
import json
import logging
import os
import threading
import time
from collections import deque
from typing import List, Optional

logger = logging.getLogger("fleet-manager")


class AuditLog:
    def __init__(self, path: Optional[str]):
        self.path = path
        self._lock = threading.Lock()
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def record(self, user: str, address: str, action: str, *, node: str = "",
               policy: str = "", namespace: str = "", enabled: Optional[bool] = None,
               ok: bool = True, detail: str = "") -> dict:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "user": user,
            "address": address,
            "action": action,
            "node": node,
            "policy": policy,
            "namespace": namespace,
            "enabled": enabled,
            "ok": ok,
            "detail": detail,
        }
        line = json.dumps(entry, sort_keys=True)
        logger.warning("audit: %s", line)
        if self.path:
            with self._lock:
                try:
                    with open(self.path, "a") as f:
                        f.write(line + "\n")
                except OSError as e:
                    logger.error("could not append to audit log %s: %s", self.path, e)
        return entry

    def tail(self, limit: int = 200) -> List[dict]:
        """Most recent `limit` entries, newest first. Unparseable lines are skipped."""
        if not self.path or not os.path.exists(self.path):
            return []
        with self._lock:
            try:
                with open(self.path) as f:
                    lines = deque(f, maxlen=max(1, limit))
            except OSError as e:
                logger.error("could not read audit log %s: %s", self.path, e)
                return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        out.reverse()
        return out
