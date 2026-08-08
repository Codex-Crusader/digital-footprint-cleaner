"""Local tracking of data-removal requests and their status.

Opting out is not a single action -- it is a slow correspondence with dozens of
companies, and brokers routinely re-list people after three to six months. A
list of "who did I write to, when, and did they actually do it" is what turns
this from a one-off scan into something that keeps working.

**Where the data lives, and why it matters.** Rows here record which sites a
person asked to be removed from. That is sensitive: it is a map of someone's
exposure plus evidence of their attempts to reduce it. So:

* Storage is a local SQLite file (``instance/tracker.sqlite3`` by default,
  overridable with ``DFC_DB_PATH``). Nothing is transmitted anywhere.
* ``instance/`` and ``*.sqlite3`` are both gitignored, so the file cannot be
  committed by accident.
* :func:`purge_all` exists so a user can delete everything in one call, and the
  UI must expose it. A privacy tool that will not forget is a contradiction.
* No search results, snippets, or scan output are stored -- only the site, the
  request's status, and the user's own notes.

Every function takes an optional ``path`` so tests can point at a temporary
file, and each call opens and closes its own connection. That is slightly less
efficient than a shared connection and considerably harder to get wrong from
Flask's worker threads.
"""

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

# What every ``path`` argument below accepts. Spelled out rather than left as
# ``Any`` so it reaches ``Path()`` and ``sqlite3.connect()`` as a type they
# actually declare -- ``Any`` silently defeats the check at exactly the boundary
# where a wrong value would be hardest to debug.
DbPath = Union[str, os.PathLike]

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "instance" / "tracker.sqlite3"

# Lifecycle of a removal request. 'reappeared' is not a failure state but the
# normal one: broker data comes back, and the tracker needs to say so.
STATUSES = (
    "todo",
    "sent",
    "acknowledged",
    "removed",
    "refused",
    "reappeared",
)
DEFAULT_STATUS = "todo"

# Statuses that still need the user to do something. Drives the dashboard's
# "needs attention" count.
OPEN_STATUSES = frozenset({"todo", "sent", "acknowledged", "refused", "reappeared"})

_MAX_TEXT = 500

# How long a write waits for a competing writer before giving up.
_LOCK_TIMEOUT_SECONDS = 5.0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS removal_requests (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name     TEXT NOT NULL,
    site_domain   TEXT NOT NULL DEFAULT '',
    opt_out_url   TEXT NOT NULL DEFAULT '',
    subject_label TEXT NOT NULL DEFAULT '',
    data_types    TEXT NOT NULL DEFAULT '[]',
    legal_basis   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'todo',
    notes         TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_removal_status ON removal_requests(status);
"""


def db_path() -> Path:
    """Return the configured database path.

    Read from the environment on every call rather than cached at import, so a
    test or a relocated deployment can change it without reloading the module.
    """
    override = os.getenv("DFC_DB_PATH", "").strip()
    return Path(override) if override else _DEFAULT_DB_PATH


def _now() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(value: Any, limit: int = _MAX_TEXT) -> str:
    """Coerce any value to a trimmed, length-capped string."""
    if value is None:
        return ""
    return str(value).strip()[:limit]


@contextmanager
def _connect(path: Optional[DbPath] = None) -> Iterator[sqlite3.Connection]:
    """Open a connection with the schema guaranteed to exist."""
    target = Path(path) if path else db_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    # timeout: two browser tabs (or two Flask worker threads) can write at the
    # same moment. Without it SQLite raises "database is locked" immediately
    # instead of waiting for the other writer to finish.
    conn = sqlite3.connect(target, timeout=_LOCK_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: Optional[DbPath] = None) -> None:
    """Create the database and schema if they do not exist yet."""
    with _connect(path):
        pass


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Convert a DB row into a plain dict a template can render."""
    item = dict(row)
    # A value read back out of SQLite is only Any-typed, and json.loads accepts
    # str/bytes/bytearray. Narrow explicitly rather than trusting the column to
    # hold what we wrote -- an older schema or a hand-edited database would
    # otherwise reach json.loads with something it cannot parse.
    stored = item.get("data_types")
    serialised = stored if isinstance(stored, (str, bytes, bytearray)) else "[]"
    try:
        item["data_types"] = json.loads(serialised or "[]")
    except (json.JSONDecodeError, TypeError):
        item["data_types"] = []
    return item


def add_request(
    site_name: str,
    site_domain: str = "",
    opt_out_url: str = "",
    subject_label: str = "",
    data_types: Optional[Sequence[str]] = None,
    legal_basis: str = "",
    status: str = DEFAULT_STATUS,
    notes: str = "",
    path: Optional[DbPath] = None,
) -> int:
    """Record a new removal request.

    Args:
        site_name: display name of the site. Required; blank input raises.
        site_domain: the site's domain, used to de-duplicate against re-scans.
        opt_out_url: the site's opt-out page, for a one-click return trip.
        subject_label: an optional label for whose footprint this is. Free text
            so the user chooses what, if anything, to record.
        data_types: data-type IDs requested for erasure.
        legal_basis: the legal basis cited.
        status: initial status; must be one of :data:`STATUSES`.
        notes: the user's own free-text notes.
        path: override the database location (used by tests).

    Returns:
        The new row's integer ID.

    Raises:
        ValueError: if ``site_name`` is blank or ``status`` is not recognised.
    """
    site_name = _clean(site_name, 200)
    if not site_name:
        raise ValueError("site_name must not be empty.")
    if status not in STATUSES:
        raise ValueError(f"Unknown status: {status!r}")

    types_json = json.dumps([_clean(t, 50) for t in (data_types or []) if _clean(t, 50)])
    now = _now()

    with _connect(path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO removal_requests
                (site_name, site_domain, opt_out_url, subject_label, data_types,
                 legal_basis, status, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                site_name,
                _clean(site_domain, 200),
                _clean(opt_out_url),
                _clean(subject_label, 200),
                types_json,
                _clean(legal_basis, 50),
                status,
                _clean(notes),
                now,
                now,
            ),
        )
    return int(cursor.lastrowid or 0)


def list_requests(
    status: Optional[str] = None,
    path: Optional[DbPath] = None,
) -> List[Dict[str, Any]]:
    """Return tracked requests, newest first, optionally filtered by status."""
    query = "SELECT * FROM removal_requests"
    params: List[Any] = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY datetime(created_at) DESC, id DESC"

    with _connect(path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_request(request_id: int, path: Optional[DbPath] = None) -> Optional[Dict[str, Any]]:
    """Return one request by ID, or None if it does not exist."""
    with _connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM removal_requests WHERE id = ?", (request_id,)
        ).fetchone()
    return _row_to_dict(row) if row else None


def update_request(
    request_id: int,
    status: Optional[str] = None,
    notes: Optional[str] = None,
    path: Optional[DbPath] = None,
) -> bool:
    """Update a request's status and/or notes.

    Returns:
        True if a row was updated, False if the ID does not exist.

    Raises:
        ValueError: if ``status`` is given but not one of :data:`STATUSES`.
    """
    if status is not None and status not in STATUSES:
        raise ValueError(f"Unknown status: {status!r}")

    fields: List[str] = []
    params: List[Any] = []
    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if notes is not None:
        fields.append("notes = ?")
        params.append(_clean(notes))
    if not fields:
        return False

    fields.append("updated_at = ?")
    params.extend([_now(), request_id])

    with _connect(path) as conn:
        cursor = conn.execute(
            f"UPDATE removal_requests SET {', '.join(fields)} WHERE id = ?", params
        )
        return cursor.rowcount > 0


def delete_request(request_id: int, path: Optional[DbPath] = None) -> bool:
    """Delete one request. Returns True if a row was removed."""
    with _connect(path) as conn:
        cursor = conn.execute("DELETE FROM removal_requests WHERE id = ?", (request_id,))
        return cursor.rowcount > 0


def purge_all(path: Optional[DbPath] = None) -> int:
    """Delete every tracked request and return how many were removed.

    Deliberately prominent: users must be able to make this tool forget
    everything without hunting for a file on disk.
    """
    with _connect(path) as conn:
        cursor = conn.execute("DELETE FROM removal_requests")
        removed = cursor.rowcount
    logger.info("Purged %d tracked removal request(s).", removed)
    return removed


def summary(path: Optional[DbPath] = None) -> Dict[str, Any]:
    """Return dashboard counters: totals, per-status counts, and open items."""
    with _connect(path) as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM removal_requests GROUP BY status"
        ).fetchall()

    by_status = {status: 0 for status in STATUSES}
    for row in rows:
        # A status written by an older version stays visible rather than
        # vanishing from the totals.
        by_status[row["status"]] = by_status.get(row["status"], 0) + row["n"]

    total = sum(by_status.values())
    return {
        "total": total,
        "by_status": by_status,
        "open": sum(n for s, n in by_status.items() if s in OPEN_STATUSES),
        "removed": by_status.get("removed", 0),
    }
