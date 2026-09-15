"""
auth.py -- the fleet manager's login: password hashing, sessions, and a
login-attempt limiter.

This is the first CertSight component that can change what a node detects,
so unlike the test console there is no unauthenticated mode. One local
admin account, password stored only as an scrypt hash in the config,
opaque random session tokens held in memory (a restart logs everyone out,
which is the right default for a control plane), and a per-address login
limiter so the password can't be brute-forced through the UI.

Everything here is stdlib: hashlib.scrypt, secrets, hmac. No third-party
auth library to keep patched on an air-gapped RPM install.
"""
import base64
import hashlib
import hmac
import secrets
import threading
import time
from typing import Dict, Optional

# scrypt parameters. N=2^14 is the conservative interactive-login setting
# (~50ms on a modern core); this only runs once per login, not per request.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_HASH_PREFIX = "scrypt"

# Roles. `admin` may change policies; `viewer` may only read -- enforced
# server-side on every write route, not just in the UI. An anonymous
# deployment (FLEET_MANAGER_ANONYMOUS_VIEWER=1) hands every visitor a
# viewer session and may have no admin account at all.
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ANONYMOUS_USER = "anonymous"

SESSION_IDLE_SECONDS = 12 * 3600
SESSION_MAX_SECONDS = 24 * 3600

LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_ATTEMPTS = 10


def hash_password(password: str) -> str:
    """
    Returns "scrypt$<salt-b64>$<hash-b64>", the string an operator puts in
    FLEET_MANAGER_ADMIN_PASSWORD_HASH. Fresh random salt every call.
    """
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
    )
    return "$".join((
        _HASH_PREFIX,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    ))


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a presented password against hash_password() output."""
    try:
        prefix, salt_b64, hash_b64 = stored.strip().split("$")
        if prefix != _HASH_PREFIX:
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
    except (ValueError, TypeError):
        return False
    if not salt or not expected:
        return False
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=len(expected),
    )
    return hmac.compare_digest(digest, expected)


class SessionStore:
    """
    Opaque token -> session record, in memory, with idle and absolute
    expiry. Tokens are 32 random bytes (urlsafe), never derived from
    anything a client controls.
    """

    def __init__(self, idle_seconds: int = SESSION_IDLE_SECONDS,
                 max_seconds: int = SESSION_MAX_SECONDS, clock=time.time):
        self._idle = idle_seconds
        self._max = max_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: Dict[str, dict] = {}

    def create(self, user: str, role: str = ROLE_ADMIN) -> str:
        token = secrets.token_urlsafe(32)
        now = self._clock()
        with self._lock:
            self._sessions[token] = {"user": user, "role": role, "created": now, "last_seen": now}
        return token

    def get(self, token: Optional[str]) -> Optional[dict]:
        """Returns the session (and bumps last_seen) or None if missing/expired."""
        if not token:
            return None
        now = self._clock()
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                return None
            if (now - session["last_seen"] > self._idle
                    or now - session["created"] > self._max):
                del self._sessions[token]
                return None
            session["last_seen"] = now
            return dict(session)

    def revoke(self, token: Optional[str]) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def prune(self) -> None:
        now = self._clock()
        with self._lock:
            stale = [
                t for t, s in self._sessions.items()
                if now - s["last_seen"] > self._idle or now - s["created"] > self._max
            ]
            for t in stale:
                del self._sessions[t]


class LoginLimiter:
    """
    Fixed-window attempt counter per client address. Refuses further
    attempts once the window's budget is spent; a successful login resets
    the address. Sized so a human typo never trips it and an online
    guess never gets a useful rate.
    """

    def __init__(self, max_attempts: int = LOGIN_MAX_ATTEMPTS,
                 window_seconds: int = LOGIN_WINDOW_SECONDS, clock=time.time):
        self._max = max_attempts
        self._window = window_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._attempts: Dict[str, list] = {}

    def allow(self, address: str) -> bool:
        now = self._clock()
        with self._lock:
            recent = [t for t in self._attempts.get(address, []) if now - t < self._window]
            if len(recent) >= self._max:
                self._attempts[address] = recent
                return False
            recent.append(now)
            self._attempts[address] = recent
            return True

    def reset(self, address: str) -> None:
        with self._lock:
            self._attempts.pop(address, None)
