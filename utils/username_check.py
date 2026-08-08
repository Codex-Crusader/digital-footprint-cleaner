# utils/username_check.py
"""Check whether a username has a public profile on a set of platforms.

The public entry point is :func:`check_username`. It sanitises the username,
requests each platform's profile URL concurrently under a hard wall-clock
budget, and returns a list of plain dicts the template layer can render as-is.

Honest limits
-------------
Naive username checkers are notoriously wrong, and a confident-but-wrong answer
in a *privacy* tool is worse than no answer at all. Three things make this hard:

* Many platforms answer a missing profile with **HTTP 200 and a "not found"
  page** (a *soft 404*), so the status code on its own proves nothing.
* Many platforms answer **403 or 429 to any non-browser client**, and to
  datacenter IPs in particular, whether or not the profile exists. An app
  deployed on a server will see far more blocking than the same code on a
  laptop, so "not blocked" is not a property of this module.
* Some platforms are single-page apps that return an identical HTML shell for
  every username; the real answer only appears once JavaScript has run.

Results are therefore **tri-state**: ``found`` / ``not_found`` / ``unknown``
-- and anything ambiguous (403, 429, 5xx, a redirect, a timeout, a connection
error, or a 200 we cannot positively confirm) is ``unknown`` with a short
machine-readable ``reason``, **never** ``not_found``. A platform whose response
cannot be interpreted honestly is marked ``SIGNAL_UNRELIABLE`` in
:data:`PLATFORMS` and is not requested at all: sending the username to a site
whose answer would be discarded anyway only leaks the query for nothing.

Every check is a ``GET``, never a ``HEAD``. Do not "optimise" that later: the
marker-based signals need the response body, and several platforms reject or
mishandle ``HEAD`` while answering ``GET`` normally, which would manufacture
ambiguity rather than remove it.

Finally, ``found`` means "this platform served a profile page for this
username". It does not mean the profile belongs to the person you have in mind.
Usernames are not identities, and common handles are reused by many people.

Scope: one username per call, by design. This tool is for auditing your own
footprint, or someone else's with their consent (see the README's "honest
limits"). Bulk enumeration is a different and worse product, so no list/CSV
input is accepted here.
"""

import logging
import re
import time
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

# httpx is declared in pyproject.toml and requirements.txt; see the note there
# about PyCharm not reading either in this project.
# noinspection PyPackageRequirements
import httpx

from utils.http_client import HttpClient

from utils.validation import clamp_text

logger = logging.getLogger(__name__)

# Hard upper bound on the username. Longer than any real handle, short enough
# that nothing interesting fits in a crafted value.
MAX_USERNAME_LENGTH = 64

# Deliberately narrower than what most platforms actually allow. Every character
# outside this set is a potential URL-structure character ("/", "?", "#", ":",
# "@", "%", whitespace), and a false rejection is far cheaper than a request
# aimed at a target the user did not ask for. Must start alphanumeric so a
# leading "." or "-" can never begin a dot-segment.
_USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# Total wall-clock budget for the whole batch. A Flask worker is blocked for the
# duration of the call, so this is a latency guarantee, not a nice-to-have.
DEFAULT_BUDGET_SECONDS = 8.0

# Bounded pool: enough parallelism to finish inside the budget, few enough
# threads that several concurrent requests cannot exhaust the process.
MAX_WORKERS = 8

CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 5.0

# Identify the tool honestly rather than impersonating a browser. Sites that
# block this are within their rights; we report that as "blocked", not as a
# missing profile.
USER_AGENT = (
    "DigitalFootprintCleaner/1.1 "
    "(+https://github.com/Codex-Crusader/digital-footprint-cleaner) "
    "public-profile-check"
)

# Result statuses. Tri-state on purpose; see the module docstring.
STATUS_FOUND = "found"
STATUS_NOT_FOUND = "not_found"
STATUS_UNKNOWN = "unknown"

# Reasons attached to an ``unknown`` result. Kept short and stable so the UI can
# map them to explanatory copy.
REASON_BLOCKED = "blocked"
REASON_RATE_LIMITED = "rate limited"
REASON_TIMEOUT = "timeout"
REASON_UNRELIABLE = "unreliable"
REASON_REDIRECTED = "redirected"
REASON_SERVER_ERROR = "server error"
REASON_UNEXPECTED = "unexpected status"
REASON_UNCONFIRMED = "unconfirmed"
REASON_NETWORK = "network error"
REASON_ERROR = "error"

# How a platform's response may be interpreted.
#
# SIGNAL_STATUS     Status code alone is trustworthy: 200 -> found,
#                   404/410 -> not_found.
# SIGNAL_SOFT_404   The platform answers 200 for every username. ``marker`` is
#                   its "no such profile" text: present -> not_found,
#                   absent -> found. Only use where that string is stable.
# SIGNAL_CONFIRM    Only positive confirmation is trustworthy: 200 containing
#                   ``marker`` -> found; any other 200 -> unknown/unconfirmed.
# SIGNAL_UNRELIABLE No trustworthy signal exists without a real browser. Never
#                   requested; always unknown/unreliable.
SIGNAL_STATUS = "status"
SIGNAL_SOFT_404 = "soft_404"
SIGNAL_CONFIRM = "confirm"
SIGNAL_UNRELIABLE = "unreliable"

_REQUEST_TIMEOUT = httpx.Timeout(
    connect=CONNECT_TIMEOUT_SECONDS,
    read=READ_TIMEOUT_SECONDS,
    write=READ_TIMEOUT_SECONDS,
    pool=CONNECT_TIMEOUT_SECONDS,
)

_REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass(frozen=True)
class Platform:
    """One checkable platform, and how to read its answer.

    Attributes:
        key: stable machine ID; becomes the ``id`` of the result dict.
        name: human-readable label for the UI.
        url_template: profile URL containing exactly one ``{username}`` field.
            The placeholder always sits in the *path*, never in the hostname, so
            no username can point the request at a different host.
        category: reuses the category keys from ``analysis.CATEGORY_META`` so
            the template can share the existing labels.
        signal: one of ``SIGNAL_STATUS``, ``SIGNAL_SOFT_404``,
            ``SIGNAL_CONFIRM`` or ``SIGNAL_UNRELIABLE``.
        marker: body substring used by the marker-based signals; ignored by
            ``SIGNAL_STATUS`` and ``SIGNAL_UNRELIABLE``.
        note: short caveat shown next to the result, mainly to explain why an
            unreliable platform was skipped.
    """

    key: str
    name: str
    url_template: str
    category: str
    signal: str
    marker: str | None = None
    note: str = ""


# The curated platform set. Biased towards services that return a clean 404 for
# a missing profile; the well-known ones that do not are still listed, marked
# unreliable, because silently dropping them would let a user assume they had
# been checked.
PLATFORMS: tuple[Platform, ...] = (
    Platform(
        key="github",
        name="GitHub",
        url_template="https://github.com/{username}",
        category="professional",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="gitlab",
        name="GitLab",
        url_template="https://gitlab.com/{username}",
        category="professional",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="devto",
        name="Dev.to",
        url_template="https://dev.to/{username}",
        category="professional",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="keybase",
        name="Keybase",
        url_template="https://keybase.io/{username}",
        category="professional",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="medium",
        name="Medium",
        url_template="https://medium.com/@{username}",
        category="professional",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="behance",
        name="Behance",
        url_template="https://www.behance.net/{username}",
        category="professional",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="reddit",
        name="Reddit",
        url_template="https://www.reddit.com/user/{username}/",
        category="forum",
        signal=SIGNAL_STATUS,
        note="Reddit rate-limits server traffic hard; expect 'blocked' as often as an answer.",
    ),
    Platform(
        key="mastodon",
        name="Mastodon (mastodon.social)",
        url_template="https://mastodon.social/@{username}",
        category="social_media",
        signal=SIGNAL_STATUS,
        note="Only the mastodon.social instance is checked; the fediverse has thousands more.",
    ),
    Platform(
        key="pinterest",
        name="Pinterest",
        url_template="https://www.pinterest.com/{username}/",
        category="social_media",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="soundcloud",
        name="SoundCloud",
        url_template="https://soundcloud.com/{username}",
        category="social_media",
        signal=SIGNAL_STATUS,
    ),
    Platform(
        key="steam",
        name="Steam",
        url_template="https://steamcommunity.com/id/{username}",
        category="social_media",
        signal=SIGNAL_SOFT_404,
        marker="The specified profile could not be found",
        note="Only custom profile URLs exist here; a numeric-ID-only account will not show up.",
    ),
    Platform(
        key="telegram",
        name="Telegram",
        url_template="https://t.me/{username}",
        category="social_media",
        signal=SIGNAL_CONFIRM,
        marker="tgme_page_title",
        note="Telegram answers 200 for every handle, so only a positive hit is trustworthy.",
    ),
    Platform(
        key="instagram",
        name="Instagram",
        url_template="https://www.instagram.com/{username}/",
        category="social_media",
        signal=SIGNAL_UNRELIABLE,
        note="Serves a login wall to non-browser clients, so no answer here would be honest.",
    ),
    Platform(
        key="x",
        name="X (Twitter)",
        url_template="https://x.com/{username}",
        category="social_media",
        signal=SIGNAL_UNRELIABLE,
        note="Profiles render only after JavaScript and login; the HTML shell is identical.",
    ),
    Platform(
        key="tiktok",
        name="TikTok",
        url_template="https://www.tiktok.com/@{username}",
        category="social_media",
        signal=SIGNAL_UNRELIABLE,
        note="Aggressive bot detection returns the same page whether or not the profile exists.",
    ),
    Platform(
        key="twitch",
        name="Twitch",
        url_template="https://www.twitch.tv/{username}",
        category="video",
        signal=SIGNAL_UNRELIABLE,
        note="Single-page app: every username returns 200 with the same shell.",
    ),
    Platform(
        key="tumblr",
        name="Tumblr",
        url_template="https://www.tumblr.com/{username}",
        category="social_media",
        signal=SIGNAL_UNRELIABLE,
        note="Redirects unauthenticated visitors to a login/consent page regardless of the blog.",
    ),
)


class UsernameCheckError(RuntimeError):
    """Raised when the whole check cannot be started.

    This covers batch-level failure only: for example an HTTP client that
    cannot be constructed. A single platform failing is never an error: it is
    reported as an ``unknown`` result with a reason.
    """


def _profile_url(platform: Platform, encoded_username: str) -> str:
    """Build the profile URL for ``platform`` from an already-encoded username."""
    return platform.url_template.format(username=encoded_username)


def _result(
    platform: Platform,
    url: str,
    status: str,
    reason: str = "",
    http_status: int | None = None,
) -> dict[str, Any]:
    """Build one result dict. See :func:`check_username` for the shape contract."""
    return {
        "id": platform.key,
        "platform": platform.name,
        "category": platform.category,
        "url": url,
        "status": status,
        "reason": reason,
        "http_status": http_status,
        "note": platform.note,
    }


def _build_client() -> httpx.Client:
    """Create the default client used when the caller injects none."""
    return httpx.Client(
        timeout=_REQUEST_TIMEOUT,
        follow_redirects=False,
        headers=dict(_REQUEST_HEADERS),
    )


def _interpret(platform: Platform, url: str, response: httpx.Response) -> dict[str, Any]:
    """Turn one HTTP response into a tri-state result dict.

    Every branch that cannot be justified from the response alone lands on
    ``unknown`` with a reason, so the caller can always explain itself.
    """
    code = response.status_code

    if code in (404, 410):
        # The only status we ever treat as proof of absence.
        return _result(platform, url, STATUS_NOT_FOUND, http_status=code)
    if code == 429:
        return _result(platform, url, STATUS_UNKNOWN, REASON_RATE_LIMITED, code)
    if code in (401, 403, 451):
        return _result(platform, url, STATUS_UNKNOWN, REASON_BLOCKED, code)
    if 300 <= code < 400:
        # Redirects are not followed and are never read as "found". A 30x away
        # from a profile URL is just as likely to be a bounce to a login wall or
        # the site homepage as it is a canonicalisation of a real profile, and
        # following it would dress up "we ended up somewhere" as a real answer.
        return _result(platform, url, STATUS_UNKNOWN, REASON_REDIRECTED, code)
    if code >= 500:
        return _result(platform, url, STATUS_UNKNOWN, REASON_SERVER_ERROR, code)
    if code != 200:
        return _result(platform, url, STATUS_UNKNOWN, REASON_UNEXPECTED, code)

    body = response.text or ""

    if platform.signal == SIGNAL_STATUS:
        return _result(platform, url, STATUS_FOUND, http_status=code)

    if platform.signal == SIGNAL_SOFT_404:
        if platform.marker and platform.marker in body:
            return _result(platform, url, STATUS_NOT_FOUND, http_status=code)
        if not platform.marker:
            # Misconfigured entry: refuse to guess rather than report a hit.
            return _result(platform, url, STATUS_UNKNOWN, REASON_UNCONFIRMED, code)
        return _result(platform, url, STATUS_FOUND, http_status=code)

    if platform.signal == SIGNAL_CONFIRM:
        if platform.marker and platform.marker in body:
            return _result(platform, url, STATUS_FOUND, http_status=code)
        # A 200 without the confirming marker means the page exists but we could
        # not verify it is a profile. That is not evidence of absence.
        return _result(platform, url, STATUS_UNKNOWN, REASON_UNCONFIRMED, code)

    return _result(platform, url, STATUS_UNKNOWN, REASON_UNRELIABLE, code)


def _check_platform(
    client: HttpClient,
    platform: Platform,
    encoded_username: str,
    deadline: float,
) -> dict[str, Any]:
    """Check a single platform. Runs on a pool thread; must not raise if avoidable."""
    url = _profile_url(platform, encoded_username)

    if platform.signal == SIGNAL_UNRELIABLE:
        # Skipped deliberately: the answer would be discarded, so making the
        # request would only hand the username to another server.
        return _result(platform, url, STATUS_UNKNOWN, REASON_UNRELIABLE)

    if time.monotonic() >= deadline:
        # Queued behind slower work and the batch budget is already spent; do
        # not start a request whose result nobody will read.
        return _result(platform, url, STATUS_UNKNOWN, REASON_TIMEOUT)

    try:
        # Timeout, headers and redirect policy are passed per request so an
        # injected client cannot silently weaken any of them.
        response = client.get(
            url,
            timeout=_REQUEST_TIMEOUT,
            headers=dict(_REQUEST_HEADERS),
            follow_redirects=False,
        )
    except httpx.TimeoutException as exc:
        logger.debug("Timeout checking %s: %s", platform.key, exc)
        return _result(platform, url, STATUS_UNKNOWN, REASON_TIMEOUT)
    except httpx.HTTPError as exc:
        logger.debug("Transport error checking %s: %s", platform.key, exc)
        return _result(platform, url, STATUS_UNKNOWN, REASON_NETWORK)

    return _interpret(platform, url, response)


def _collect(
    submitted: Sequence[tuple[Platform, Future[dict[str, Any]]]],
    encoded_username: str,
) -> dict[int, dict[str, Any]]:
    """Drain finished futures into results, keyed by their submission index."""
    collected: dict[int, dict[str, Any]] = {}
    for index, (platform, future) in enumerate(submitted):
        url = _profile_url(platform, encoded_username)
        if future.cancelled() or not future.done():
            # The batch budget expired before this platform answered.
            collected[index] = _result(platform, url, STATUS_UNKNOWN, REASON_TIMEOUT)
            continue
        try:
            collected[index] = future.result()
        except Exception as exc:  # noqa: BLE001 - one platform must never kill the batch
            # Type only: exception text can embed the profile URL, which carries
            # the username being checked. Full detail stays at debug level.
            logger.warning(
                "Username check failed for %s: %s", platform.key, type(exc).__name__
            )
            logger.debug("Username check failure detail for %s", platform.key,
                         exc_info=True)
            collected[index] = _result(platform, url, STATUS_UNKNOWN, REASON_ERROR)
    return collected


def check_username(
    username: object,
    client: HttpClient | None = None,
    platforms: Sequence[Platform] | None = None,
    *,
    budget: float | None = None,
) -> list[dict[str, Any]]:
    """Check ``username`` against ``platforms`` and return one dict per platform.

    Results come back in the same order as ``platforms``, so the template can
    render them without sorting. Each dict has a stable shape::

        {
            "id":          "github",              # Platform.key
            "platform":    "GitHub",              # display name
            "category":    "professional",        # analysis.CATEGORY_META key
            "url":         "https://github.com/octocat",
            "status":      "found" | "not_found" | "unknown",
            "reason":      "",                    # non-empty only when unknown
            "http_status": 200,                   # int, or None if no response
            "note":        "",                    # platform caveat, may be empty
        }

    ``reason`` is one of ``blocked``, ``rate limited``, ``timeout``,
    ``unreliable``, ``redirected``, ``server error``, ``unexpected status``,
    ``unconfirmed``, ``network error`` or ``error``.

    All platforms are checked concurrently on a bounded thread pool under a
    single wall-clock budget; whatever has not answered when the budget expires
    is reported as ``unknown``/``timeout``. The call therefore returns within
    roughly ``budget`` seconds no matter how slow any platform is, which is what
    keeps a Flask worker from being pinned by one bad host.

    Args:
        username: the handle to look for. Non-string values are treated as
            empty. Trimmed, length-capped, restricted to
            ``[A-Za-z0-9][A-Za-z0-9._-]*`` and URL-encoded before use.
        client: optional ``httpx.Client`` to use for every request. ``httpx``
            clients are thread-safe, so one instance is shared across the pool.
            When omitted, one is created with explicit timeouts and closed
            before returning; an injected client is never closed. Injecting a
            fake is how the tests stay off the network.
        platforms: optional subset of :data:`PLATFORMS` to check.
        budget: total wall-clock seconds for the whole batch. Defaults to
            :data:`DEFAULT_BUDGET_SECONDS`.

    Returns:
        A list of result dicts, one per entry in ``platforms``, in that order.

    Raises:
        ValueError: if ``username`` is empty after trimming, or contains
            anything outside the allowed character set.
        UsernameCheckError: if the batch cannot be started at all (e.g. the
            default HTTP client cannot be constructed). A single platform
            failing never raises.
    """
    username = clamp_text(username, MAX_USERNAME_LENGTH)
    if not username:
        raise ValueError("Username must not be empty.")
    # ".." is the one sequence the character class above still permits that has
    # structural meaning in a URL path, and percent-encoding does not neutralise
    # it, so it is rejected outright.
    # ``fullmatch``, not ``match``: with ``$`` a trailing newline still matches,
    # and ``clamp_text`` strips *before* truncating, so a long value ending in
    # "\nb" can be cut back down to one ending in "\n".
    if not _USERNAME_RE.fullmatch(username) or ".." in username:
        raise ValueError("Username contains characters that are not allowed.")

    # Belt and braces: the character set already excludes every URL delimiter,
    # and encoding guarantees the value stays a single path segment even if that
    # set is ever widened.
    encoded_username = quote(username, safe="")

    selected = list(PLATFORMS) if platforms is None else list(platforms)
    if not selected:
        return []

    budget_seconds = DEFAULT_BUDGET_SECONDS if budget is None else float(budget)
    deadline = time.monotonic() + max(0.0, budget_seconds)

    owns_client = client is None
    if client is None:
        try:
            client = _build_client()
        except Exception as exc:  # noqa: BLE001 - normalise any client failure
            logger.warning("Could not create HTTP client: %s", exc)
            raise UsernameCheckError("The username checker is unavailable.") from exc

    try:
        # Not a `with` block on purpose: ThreadPoolExecutor.__exit__ waits for
        # every worker, which would quietly turn the hard budget into "as long
        # as the slowest platform takes".
        executor = ThreadPoolExecutor(
            max_workers=min(MAX_WORKERS, len(selected)),
            thread_name_prefix="username-check",
        )
        submitted: list[tuple[Platform, Future[dict[str, Any]]]] = []
        try:
            for platform in selected:
                submitted.append(
                    (
                        platform,
                        executor.submit(
                            _check_platform, client, platform, encoded_username, deadline
                        ),
                    )
                )
            wait(
                [future for _, future in submitted],
                timeout=max(0.0, deadline - time.monotonic()),
            )
        finally:
            # Never wait here either; stragglers are already bounded by the
            # per-request timeouts and their results are simply discarded.
            executor.shutdown(wait=False, cancel_futures=True)

        collected = _collect(submitted, encoded_username)
        return [collected[index] for index in range(len(submitted))]
    finally:
        if owns_client:
            # Close only what we opened; an injected client belongs to the
            # caller and may be reused for other requests.
            client.close()
