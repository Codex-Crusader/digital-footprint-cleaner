"""Optional passcode lock and localhost hardening for a sensitive local tool.

This app is a map of one person's exposure. The scan page shows where they can
be found; the tracker records what they have tried to remove and what is still
outstanding. That is worth protecting even on a machine only they use, so this
module provides two independent defences.

**1. Host-header allowlist (always on).** A local web app is reachable from any
web page the user happens to have open, because a browser will happily resolve
an attacker-controlled hostname to 127.0.0.1 and then talk to whatever is
listening there. That is DNS rebinding, and it defeats the same-origin policy by
making the attacker's origin *be* the app's origin. CSRF tokens do not help,
because a rebound page can read the token out of the page it just fetched.

The fix is to check the Host header against an allowlist. A browser sends the
hostname the user typed, so a rebound request arrives with the attacker's
hostname and is refused before it reaches a route. This costs nothing and is the
single most valuable control for a service bound to loopback.

**2. Passcode lock (opt-in).** When ``DFC_PASSCODE`` (or a pre-computed
``DFC_PASSCODE_HASH``) is set, every page requires a login first. Deliberately
opt-in: a tool that demands credential setup before it will run once is a tool
people stop using, and on a single-user laptop the honest security gain over the
host check is modest. When it is not set, the UI says so plainly rather than
implying a protection that is not there.

Storage and comparison follow the usual rules. The passcode is never held in
memory in plaintext beyond hashing it at startup; verification uses PBKDF2-
HMAC-SHA256 with a per-installation random salt and a constant-time compare, so
neither a memory dump nor a timing measurement yields the passcode. Login
attempts are throttled per client address, because a four-digit passcode against
an unthrottled endpoint is not a lock at all.

Standard library only. Adding an auth framework for one passcode would be a
larger attack surface than the thing it protects.
"""

import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# PBKDF2 cost. Deliberately high: this runs once per login attempt on a local
# machine, so a few hundred milliseconds is imperceptible to the user and
# expensive for anyone grinding guesses.
_PBKDF2_ROUNDS = 600_000
_SALT_BYTES = 16

# Login throttling. Five attempts per window per client address, then a lockout.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300

# How long a session may sit idle before it must be unlocked again. A privacy
# tool left open on an unattended screen is exactly the exposure it exists to
# reduce.
IDLE_TIMEOUT_SECONDS = int(os.getenv("DFC_IDLE_TIMEOUT", "1800"))

# Hostnames a request may claim to be for. Anything else is refused: see the
# module docstring on DNS rebinding. Extra names can be added for a deployment
# that genuinely serves a hostname, via DFC_ALLOWED_HOSTS.
_DEFAULT_HOSTS = ("localhost", "127.0.0.1", "[::1]", "::1")


def allowed_hosts() -> frozenset:
    """Hostnames this app will answer to, lowercased and without a port."""
    extra = os.getenv("DFC_ALLOWED_HOSTS", "")
    names = [h.strip().lower() for h in extra.split(",") if h.strip()]
    return frozenset(_DEFAULT_HOSTS) | frozenset(names)


def host_is_allowed(host_header: Optional[str]) -> bool:
    """True if ``host_header`` names a host this app should answer to.

    The port is stripped before comparison: the port a user connects on is not
    a security boundary, the hostname is. An absent Host header is refused,
    since every HTTP/1.1 client sends one and its absence signals a handcrafted
    request.
    """
    if not host_header:
        return False
    host = host_header.strip().lower()
    # Strip the port, taking care not to break an IPv6 literal like [::1]:5000.
    if host.startswith("["):
        closing = host.find("]")
        if closing != -1:
            host = host[: closing + 1]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    return host in allowed_hosts()


def hash_passcode(passcode: str, salt: Optional[bytes] = None) -> str:
    """Return a ``pbkdf2_sha256$rounds$salt$hash`` string for ``passcode``."""
    if salt is None:
        salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256", passcode.encode("utf-8"), salt, _PBKDF2_ROUNDS
    )
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${derived.hex()}"


def verify_passcode(passcode: str, stored: str) -> bool:
    """Constant-time check of ``passcode`` against a :func:`hash_passcode` string.

    Returns False for a malformed stored value rather than raising: a corrupted
    environment variable must fail closed, not crash the request.
    """
    if not passcode or not stored:
        return False
    try:
        algorithm, rounds, salt_hex, expected_hex = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", passcode.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds)
        )
    except (ValueError, TypeError):
        logger.warning("Stored passcode hash is malformed; refusing all logins.")
        return False
    return hmac.compare_digest(derived.hex(), expected_hex)


def configured_hash() -> str:
    """The passcode hash this installation should check against, or "".

    ``DFC_PASSCODE_HASH`` is preferred, because it keeps the plaintext out of
    the environment (and therefore out of shell history, process listings and
    crash reports). ``DFC_PASSCODE`` is accepted for convenience and hashed at
    startup.
    """
    stored = os.getenv("DFC_PASSCODE_HASH", "").strip()
    if stored:
        return stored
    plain = os.getenv("DFC_PASSCODE", "").strip()
    if plain:
        logger.info(
            "Passcode lock enabled from DFC_PASSCODE. Prefer DFC_PASSCODE_HASH "
            "so the plaintext is not in the environment."
        )
        return hash_passcode(plain)
    return ""


class LoginThrottle:
    """Per-client attempt limiter for the login endpoint.

    Keyed by client address. Successful logins clear the counter so a user who
    mistypes twice and then succeeds is not penalised.
    """

    def __init__(
        self,
        max_attempts: int = LOGIN_MAX_ATTEMPTS,
        window_seconds: int = LOGIN_WINDOW_SECONDS,
    ) -> None:
        self._max = max(1, int(max_attempts))
        self._window = float(window_seconds)
        self._lock = threading.Lock()
        self._attempts: dict = {}

    def _prune_locked(self, now: float) -> None:
        stale = [k for k, (_, last) in self._attempts.items() if now - last > self._window]
        for key in stale:
            self._attempts.pop(key, None)

    def is_locked_out(self, client: str) -> bool:
        """True if ``client`` has spent its attempts within the window."""
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            count, last = self._attempts.get(client, (0, 0.0))
            return count >= self._max and now - last <= self._window

    def record_failure(self, client: str) -> None:
        """Count a failed attempt against ``client``."""
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            count, _ = self._attempts.get(client, (0, 0.0))
            self._attempts[client] = (count + 1, now)

    def record_success(self, client: str) -> None:
        """Clear ``client``'s failure count after a correct passcode."""
        with self._lock:
            self._attempts.pop(client, None)

    def seconds_remaining(self, client: str) -> int:
        """How long until ``client`` may try again. 0 when not locked out."""
        now = time.time()
        with self._lock:
            count, last = self._attempts.get(client, (0, 0.0))
            if count < self._max:
                return 0
            return max(0, int(self._window - (now - last)))

    def reset(self) -> None:
        """Forget every recorded attempt. Public hook used by tests."""
        with self._lock:
            self._attempts.clear()


def session_is_fresh(unlocked_at: object, now: Optional[float] = None) -> bool:
    """True if a session unlocked at ``unlocked_at`` has not gone idle.

    A non-numeric value counts as stale, so a tampered or truncated cookie locks
    the app rather than unlocking it.
    """
    if not isinstance(unlocked_at, (int, float)) or isinstance(unlocked_at, bool):
        return False
    elapsed = (time.time() if now is None else now) - float(unlocked_at)
    return 0 <= elapsed <= IDLE_TIMEOUT_SECONDS


def describe_protection(lock_enabled: bool) -> Tuple[str, str]:
    """Return ``(state, explanation)`` for the UI to show about protection.

    The unlocked case is stated plainly. A privacy tool that lets someone assume
    a protection it does not have has misled them about the one thing they came
    here to check.
    """
    if lock_enabled:
        return (
            "locked",
            "This app is passcode protected and only answers requests addressed "
            "to localhost.",
        )
    return (
        "unlocked",
        "No passcode is set, so anyone with access to this computer can open "
        "this page. Set DFC_PASSCODE to require one. Requests are still "
        "restricted to localhost.",
    )
