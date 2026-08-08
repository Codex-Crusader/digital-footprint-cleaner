"""Short-lived, server-side storage for the URLs a scan turned up.

The petition form posts back a list of result *IDs*, and something has to
remember which URL each ID meant. That map used to live in the Flask session,
which worked only because the old scan returned at most ten results.

A deep scan returns well over a hundred. Flask sessions are client-side signed
cookies, browsers cap a cookie at roughly 4KB, and Werkzeug's response to an
oversized one is a warning on the server and silent truncation at the browser.
The failure that produces is nasty precisely because it is quiet: the scan looks
fine, the user ticks twenty sites, and the petition step reports it could not
generate anything: with nothing anywhere saying why.

**Why in memory and not on disk.** :mod:`utils.tracker` states plainly that no
search results, snippets or scan output are ever written to disk, because a scan
is a map of one person's exposure. Persisting the result map to buy convenience
would quietly break that promise, so this store keeps everything in the process,
bounded by a TTL and a hard cap on retained sessions, and the session cookie
carries nothing but an opaque token.

The trade-off, stated as plainly as the rate limiter states its own: this is
per-process. Under multiple workers a request can land on a worker that never
saw the scan, and the user is asked to search again: the same failure mode the
old cookie had when the session expired, and handled by the same message. A
multi-worker deployment wanting better should put a shared cache behind this
class's three methods.
"""

import secrets
import threading
import time
from typing import Dict, Mapping, Optional, Tuple

# How long a scan's results stay retrievable. Long enough to read a report and
# tick boxes; short enough that a shared machine does not hold someone's
# footprint in memory all day.
DEFAULT_TTL_SECONDS = 30 * 60

# Hard cap on retained scans. Without it, a crawler hitting the search endpoint
# would grow this map without limit: a slow memory exhaustion bug.
DEFAULT_MAX_SESSIONS = 250

# Cap on entries in a single scan's map, mirroring the scanner's own result cap.
DEFAULT_MAX_ENTRIES = 500


class ResultStore:
    """Token-addressed, expiring map of result ID to URL.

    Thread-safe: Flask's development server and most WSGI deployments handle
    requests on multiple threads, so every mutation takes the lock.
    """

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self._ttl = float(ttl_seconds)
        self._max_sessions = max(1, int(max_sessions))
        self._max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        # token -> (stored_at, {result_id: url})
        self._entries: Dict[str, Tuple[float, Dict[str, str]]] = {}

    def _purge_locked(self, now: float, reserve: int = 0) -> None:
        """Drop expired entries, then the oldest ones if still over capacity.

        ``reserve`` is how many entries the caller is about to add. Purging
        without it leaves exactly enough room for the current contents and then
        overshoots the cap by one on every insert.

        Eviction order is dict insertion order rather than the stored
        timestamp. ``time.time()`` has millisecond-ish resolution on Windows, so
        several scans within one tick share a timestamp and sorting by it picks
        an arbitrary victim; :meth:`put` re-inserts on overwrite specifically so
        that insertion order tracks recency.

        Caller must hold the lock.
        """
        expired = [t for t, (stored_at, _) in self._entries.items() if now - stored_at > self._ttl]
        for token in expired:
            self._entries.pop(token, None)

        overflow = len(self._entries) + max(0, reserve) - self._max_sessions
        if overflow > 0:
            for token in list(self._entries)[:overflow]:
                self._entries.pop(token, None)

    def put(self, mapping: Mapping[str, str], token: Optional[str] = None) -> str:
        """Store ``mapping`` and return the token that retrieves it.

        Passing an existing ``token`` overwrites that slot, so a user running
        several scans in one session does not accumulate a new retained map per
        scan. A fresh token is minted when none is given.
        """
        token = token or secrets.token_urlsafe(16)
        trimmed = {
            str(key): str(value)
            for key, value in list(mapping.items())[: self._max_entries]
        }
        now = time.time()
        with self._lock:
            # Remove first so the re-insert moves this token to the end, keeping
            # dict order equal to recency order for eviction.
            self._entries.pop(token, None)
            self._purge_locked(now, reserve=1)
            self._entries[token] = (now, trimmed)
        return token

    def get(self, token: object) -> Dict[str, str]:
        """Return the stored map for ``token``, or an empty map.

        An empty map is returned for an unknown, expired or malformed token
        alike. The caller cannot act on the difference: every case means
        "ask the user to run the search again": and collapsing them here
        keeps that decision in one place.
        """
        if not isinstance(token, str) or not token:
            return {}
        now = time.time()
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return {}
            stored_at, mapping = entry
            if now - stored_at > self._ttl:
                self._entries.pop(token, None)
                return {}
            return dict(mapping)

    def drop(self, token: object) -> None:
        """Forget one stored map. Used when a session is cleared."""
        if not isinstance(token, str) or not token:
            return
        with self._lock:
            self._entries.pop(token, None)

    def clear(self) -> None:
        """Forget everything. Public hook used by tests."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        """How many scans are currently retained."""
        with self._lock:
            return len(self._entries)


# The application-wide instance. Module-level for the same reason the rate
# limiter is: it must be shared by every request in the process to work at all.
store = ResultStore()
