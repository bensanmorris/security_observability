import logging
import threading
from collections import OrderedDict
from typing import OrderedDict as OrderedDictType

from .constants import CACHE_MIN_SIZE, CACHE_MAX_SIZE

logger = logging.getLogger(__name__)


class LRUCache:
    """
    A dict-like LRU cache backed by OrderedDict.

    On every get/set the accessed key is moved to the end (most-recently-used).
    When the cap is reached the front entry (least-recently-used) is evicted.

    Used for all three caches in CertificateAnalyzer:
      - known_certs         (path:index:serial → CertificateInfo)
      - processed_paths     (path → True)
      - password_failed_paths (path → True)

    Evicting from known_certs / processed_paths gives evicted certs a chance
    to be re-analysed if they become active again.  Evicting from
    password_failed_paths gives previously-failed keystores a second chance,
    which is desirable if the operator has since set JKS_PASSWORD.

    Thread-safety: an RLock guards every public method so concurrent event
    threads cannot race on check-then-modify sequences.  keys()/items()/values()
    and __iter__ return snapshots (lists) so callers can iterate safely after
    releasing the lock.
    """

    def __init__(self, maxsize: int = CACHE_MAX_SIZE):
        if maxsize < CACHE_MIN_SIZE:
            logger.warning(
                f"CACHE_MAX_SIZE {maxsize} is below minimum {CACHE_MIN_SIZE}; "
                f"using {CACHE_MIN_SIZE}."
            )
            maxsize = CACHE_MIN_SIZE
        self.maxsize = maxsize
        self._store: OrderedDict = OrderedDict()
        self._lock = threading.RLock()

    # ── dict-like interface ───────────────────────────────────────────────────

    def __contains__(self, key) -> bool:
        with self._lock:
            return key in self._store

    def __getitem__(self, key):
        with self._lock:
            self._store.move_to_end(key)
            return self._store[key]

    def __setitem__(self, key, value) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._store[key] = value
            else:
                if len(self._store) >= self.maxsize:
                    evicted_key, _ = self._store.popitem(last=False)
                    logger.debug(f"LRU eviction: {evicted_key}")
                self._store[key] = value

    def __delitem__(self, key) -> None:
        with self._lock:
            del self._store[key]

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def __iter__(self):
        with self._lock:
            return iter(list(self._store))

    def get(self, key, default=None):
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                return self._store[key]
            return default

    def items(self):
        with self._lock:
            return list(self._store.items())

    def keys(self):
        with self._lock:
            return list(self._store.keys())

    def values(self):
        with self._lock:
            return list(self._store.values())

    def add(self, key) -> None:
        """Set-like interface for password_failed_paths."""
        self[key] = True

    def discard(self, key) -> None:
        """Set-like discard — no error if key absent."""
        with self._lock:
            if key in self._store:
                del self._store[key]

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
