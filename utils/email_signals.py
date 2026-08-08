"""Public-exposure signals for a single email address.

Given an email, three independent probes ask *public* endpoints what the wider
internet already knows about its owner:

* **Gravatar avatar**: whether an avatar image exists for the address.
* **Gravatar profile**: the public profile document, which can expose a real
  name, employer, location and linked social accounts from an email alone.
  This is the highest-value signal of the three.
* **GitHub user search**: accounts that published this address.

The single public entry point is :func:`gather_email_signals`. It returns a
plain dict of strings, lists and dicts that a Jinja template can render
directly; the exact shape is documented on that function and is stable.

Honest limits
-------------
* Every probe is *tri-state*: ``found`` / ``not_found`` / ``unknown``. A probe
  that could not complete (timeout, network error, rate limiting) resolves to
  ``unknown``, never to ``not_found``. Reporting "no exposure found" when we
  simply failed to look would be a privacy lie, so the template **must** render
  the two states differently.
* Even on a clean run, absence of evidence is not evidence of absence. These
  are three endpoints out of thousands, and GitHub can only find users who
  chose to make their email public: most people return zero results.
* GitHub's search API allows roughly ten unauthenticated requests per minute
  per IP, so ``unknown`` is a routine outcome under any real traffic. Set a
  ``GITHUB_TOKEN`` environment variable to raise that ceiling.
* The Gravatar profile payload is *user-controlled content*. Every URL taken
  from it is validated with :func:`utils.validation.is_safe_http_url` before
  being handed back, because the template renders these values as links.
* The email address is PII. It is never logged above DEBUG; INFO and above see
  only a redacted form.
"""

import hashlib
import logging
import os
import re
import time
from typing import Any

# httpx is declared in pyproject.toml and requirements.txt; see the note there
# about PyCharm not reading either in this project.
# noinspection PyPackageRequirements
import httpx

from utils.http_client import HttpClient

from utils.validation import (
    MAX_QUERY_LENGTH,
    clamp_text,
    is_safe_http_url,
)

logger = logging.getLogger(__name__)

# A probe result dict. Aliased for readability; it is a plain dict so the
# template layer never has to know about this module's types.
Signals = dict[str, Any]

# The three states every probe resolves to. ``UNKNOWN`` means "we could not
# find out", which is deliberately distinct from ``NOT_FOUND``.
FOUND = "found"
NOT_FOUND = "not_found"
UNKNOWN = "unknown"

# Identifying ourselves is basic etiquette against public APIs, and GitHub
# rejects requests without a User-Agent outright.
USER_AGENT = (
    "DigitalFootprintCleaner/1.1 (privacy self-audit; "
    "+https://github.com/Codex-Crusader/digital-footprint-cleaner)"
)

# Separate connect/read budgets: a dead host should fail fast, but a slow
# responder deserves a little longer once the connection is up.
CONNECT_TIMEOUT_SECONDS = 5.0
READ_TIMEOUT_SECONDS = 8.0

# Ceiling on the whole gather. Checked *between* probes, so the true worst case
# is this budget plus one in-flight request; it bounds the number of probes we
# start, not the one already running.
TOTAL_BUDGET_SECONDS = 20.0

# Caps on untrusted profile content so a hostile or bloated Gravatar payload
# cannot blow up the rendered page.
MAX_FIELD_LENGTH = 200
MAX_URL_LENGTH = 2000
MAX_ACCOUNTS = 12
MAX_EMAILS = 5
MAX_GITHUB_USERS = 5

_GRAVATAR_AVATAR_URL = "https://www.gravatar.com/avatar/{digest}"
_GRAVATAR_PROFILE_URL = "https://www.gravatar.com/{digest}.json"
_GITHUB_SEARCH_URL = "https://api.github.com/search/users"

# Deliberately minimal: one "@", no whitespace, and a dotted domain. This is a
# sanity check to avoid wasting network calls on obvious junk, *not* an RFC
# 5322 parser: writing one of those correctly is a project in itself, and
# adding a dependency for it is not worth it here.
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$")

_TIMEOUT = httpx.Timeout(
    connect=CONNECT_TIMEOUT_SECONDS,
    read=READ_TIMEOUT_SECONDS,
    write=READ_TIMEOUT_SECONDS,
    pool=CONNECT_TIMEOUT_SECONDS,
)


class EmailSignalError(RuntimeError):
    """Raised when one of the public endpoints is unavailable or misbehaves.

    This is distinct from *"the probe succeeded but found nothing"*, which is
    represented by the ``not_found`` state.

    :func:`gather_email_signals` never propagates this: it catches the error at
    each probe boundary and reports that probe as ``unknown``, because a failed
    lookup must never crash the page or be mistaken for a clean result. The
    type is public so callers reusing the request helper can distinguish a
    backend failure from a programming error.
    """


def _redact(email: str) -> str:
    """Return a log-safe form of ``email`` such as ``j***@example.com``.

    The domain is kept because it is useful when debugging endpoint behaviour
    and is not personally identifying on its own.
    """
    local, _, domain = email.partition("@")
    first = local[0] if local else "?"
    return f"{first}***@{domain}" if domain else "***"


def normalise_email(email: object) -> str:
    """Trim, length-limit and lowercase ``email``, rejecting obvious junk.

    Gravatar hashes the lowercased, stripped address, so normalisation is part
    of the protocol here rather than mere tidiness.

    Args:
        email: raw user input; any type is accepted so callers never have to
            pre-validate (mirrors :func:`utils.validation.clamp_text`).

    Returns:
        The normalised address.

    Raises:
        ValueError: if the value is empty or not plausibly an email address.
    """
    cleaned = clamp_text(email, MAX_QUERY_LENGTH).lower()
    if not cleaned:
        raise ValueError("Email address must not be empty.")
    if not _EMAIL_PATTERN.match(cleaned):
        # Do not echo the input back in the message: it flows into flash
        # messages and logs, and it is PII.
        raise ValueError("That does not look like a valid email address.")
    return cleaned


def email_digest(email: str) -> str:
    """Return the SHA-256 hex digest Gravatar keys its records by.

    SHA-256 rather than the historically documented MD5: MD5 trips security
    linters, and this project advertises hardening. Gravatar serves both, and
    the SHA-256 form is verified working against the live endpoints.
    """
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


def _build_client() -> httpx.Client:
    """Create the default HTTP client used when the caller injects none.

    Redirects are followed but capped. httpx refuses to dispatch a redirect to
    a non-http(s) scheme and raises instead, which the request helper turns
    into an ``unknown`` state: so a hostile ``Location`` header cannot lead us
    anywhere dangerous.
    """
    return httpx.Client(
        timeout=_TIMEOUT,
        follow_redirects=True,
        max_redirects=3,
        headers={"User-Agent": USER_AGENT},
    )


def _request(
    client: HttpClient,
    url: str,
    label: str,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """GET ``url`` and return the response, normalising any failure.

    The timeout is passed per request rather than relying on the client's
    default, so an injected client configured without one (or with
    ``timeout=None``) still cannot hang the page.

    Args:
        client: the HTTP client to use.
        url: absolute endpoint URL. Must never contain the email address,
            see the logging note below.
        label: short static probe name used in log messages.
        params: optional query parameters.
        headers: optional extra headers, merged over the default User-Agent.

    Returns:
        The raw response, whatever its status code. Status handling is each
        probe's own business.

    Raises:
        EmailSignalError: on any transport-level failure (DNS, timeout,
            refused connection, unsupported redirect scheme, malformed URL).
    """
    merged_headers = {"User-Agent": USER_AGENT}
    if headers:
        merged_headers.update(headers)

    try:
        return client.get(url, params=params, headers=merged_headers, timeout=_TIMEOUT)
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        # Log only the static label and the exception *class*. Several httpx
        # exceptions stringify with the full request URL, and the GitHub probe
        # carries the email in its query string: formatting the exception
        # here would leak PII into the logs at WARNING level.
        logger.warning("%s probe failed: %s", label, type(exc).__name__)
        raise EmailSignalError(f"The {label} lookup is currently unavailable.") from exc


def _text(value: object) -> str | None:
    """Return a trimmed, length-capped string, or ``None`` if there isn't one.

    Every Gravatar profile key is optional and the payload shape varies per
    user, so non-string and missing values collapse to ``None`` rather than
    raising.
    """
    text = clamp_text(value, MAX_FIELD_LENGTH)
    return text or None


def _safe_url(value: object) -> str | None:
    """Return ``value`` only if it is a plain http(s) URL, else ``None``.

    Profile URLs come from user-controlled Gravatar data and are rendered as
    ``href`` values, so ``javascript:`` and ``data:`` payloads must be dropped
    here rather than in the template. Callers keep the surrounding record and
    simply render no link.
    """
    if not is_safe_http_url(value):
        return None
    return clamp_text(value, MAX_URL_LENGTH) or None


def _as_list(value: object) -> list[Any]:
    """Coerce a possibly-missing, possibly-wrong-typed JSON field to a list."""
    return value if isinstance(value, list) else []


def _avatar_result(state: str, url: str | None, detail: str) -> Signals:
    """Build the avatar probe's result dict. Every key is always present."""
    return {"state": state, "url": url, "detail": detail}


def _profile_result(state: str, detail: str, entry: dict[str, Any] | None = None) -> Signals:
    """Build the profile probe's result dict from an optional Gravatar entry.

    Keys are fixed regardless of what the payload contained, so a template can
    reference any of them unconditionally.
    """
    entry = entry or {}
    accounts = []
    for raw in _as_list(entry.get("accounts"))[:MAX_ACCOUNTS]:
        if not isinstance(raw, dict):
            continue
        accounts.append(
            {
                "domain": _text(raw.get("domain")),
                "display": _text(raw.get("display")),
                "shortname": _text(raw.get("shortname")),
                # None when the URL is unsafe: the user still learns an account
                # exists on that domain, we just refuse to link to it.
                "url": _safe_url(raw.get("url")),
            }
        )

    emails = []
    for raw_email in _as_list(entry.get("emails"))[:MAX_EMAILS]:
        value = raw_email.get("value") if isinstance(raw_email, dict) else raw_email
        text = _text(value)
        if text:
            emails.append(text)

    return {
        "state": state,
        "detail": detail,
        "profile_url": _safe_url(entry.get("profileUrl")),
        "username": _text(entry.get("preferredUsername")),
        "display_name": _text(entry.get("displayName")),
        "thumbnail_url": _safe_url(entry.get("thumbnailUrl")),
        "location": _text(entry.get("currentLocation")),
        "job_title": _text(entry.get("job_title")),
        "company": _text(entry.get("company")),
        "pronouns": _text(entry.get("pronouns")),
        "about_me": _text(entry.get("aboutMe")),
        "accounts": accounts,
        "emails": emails,
    }


def _github_result(state: str, detail: str, total_count: int = 0,
                   users: list[Signals] | None = None) -> Signals:
    """Build the GitHub probe's result dict. Every key is always present."""
    return {
        "state": state,
        "detail": detail,
        "total_count": total_count,
        "users": users or [],
    }


def _probe_avatar(client: HttpClient, digest: str) -> Signals:
    """Check whether a Gravatar avatar exists for ``digest``.

    ``?d=404`` disables the default fallback image, so HTTP 200 means a real
    avatar exists and 404 means none does. Any other outcome is ``unknown``.
    """
    probe_url = _GRAVATAR_AVATAR_URL.format(digest=digest)
    try:
        response = _request(
            client, probe_url, "Gravatar avatar",
            params={"d": "404"}, headers={"Accept": "image/*"},
        )
    except EmailSignalError as exc:
        return _avatar_result(UNKNOWN, None, str(exc))

    if response.status_code == 200:
        # Hand back the plain URL (no ``d=404``) so the template can show it.
        return _avatar_result(FOUND, probe_url, "A Gravatar avatar is published for this address.")
    if response.status_code == 404:
        return _avatar_result(NOT_FOUND, None, "No Gravatar avatar is published for this address.")
    return _avatar_result(
        UNKNOWN, None, f"Gravatar returned an unexpected status ({response.status_code})."
    )


def _probe_profile(client: HttpClient, digest: str) -> Signals:
    """Fetch and defensively parse the public Gravatar profile for ``digest``.

    The payload is shaped ``{"entry": [ {...} ]}`` and every key inside is
    optional, so anything unexpected degrades to ``None`` or an empty list
    instead of raising.
    """
    url = _GRAVATAR_PROFILE_URL.format(digest=digest)
    try:
        response = _request(client, url, "Gravatar profile", headers={"Accept": "application/json"})
    except EmailSignalError as exc:
        return _profile_result(UNKNOWN, str(exc))

    if response.status_code == 404:
        return _profile_result(NOT_FOUND, "No public Gravatar profile exists for this address.")
    if response.status_code != 200:
        # Check the status *before* parsing: Gravatar serves an HTML body on
        # error pages, which would otherwise blow up as malformed JSON.
        return _profile_result(
            UNKNOWN, f"Gravatar returned an unexpected status ({response.status_code})."
        )

    try:
        payload = response.json()
    except ValueError:
        # json.JSONDecodeError subclasses ValueError, not httpx.HTTPError, so
        # this must be caught separately or it escapes to the caller.
        logger.warning("Gravatar profile probe returned a non-JSON body.")
        return _profile_result(UNKNOWN, "The Gravatar profile response could not be read.")

    # Absence is signalled by 404, handled above. A 200 whose body is not the
    # documented {"entry": [...]} shape is an anomaly: a proxy, a captive
    # portal, or an API change: not evidence that no profile exists. Reporting
    # it as "not found" would tell the user they are clean when we never looked.
    if not isinstance(payload, dict) or not isinstance(payload.get("entry"), list):
        return _profile_result(
            UNKNOWN, "The Gravatar profile response was not in the expected format."
        )

    entry = next((e for e in payload["entry"] if isinstance(e, dict)), None)
    if entry is None:
        return _profile_result(NOT_FOUND, "No public Gravatar profile exists for this address.")
    return _profile_result(FOUND, "A public Gravatar profile exists for this address.", entry)


def _probe_github(client: HttpClient, email: str) -> Signals:
    """Search GitHub for users who published ``email`` on their account.

    Sends ``GITHUB_TOKEN`` as a bearer token when the environment provides one,
    which lifts the search quota well above the unauthenticated ten requests
    per minute. Rate limiting and auth failures resolve to ``unknown``: with a
    quota this small, treating a throttled request as "nothing found" would
    mislabel most lookups.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        # The email travels as a query *parameter*, keeping it out of the URL
        # constant that failure paths log.
        response = _request(
            client, _GITHUB_SEARCH_URL, "GitHub user search",
            params={"q": f"{email} in:email"}, headers=headers,
        )
    except EmailSignalError as exc:
        return _github_result(UNKNOWN, str(exc))

    if response.status_code in (403, 429):
        return _github_result(
            UNKNOWN,
            "GitHub rate-limited this lookup, so its results are unknown. "
            "Set a GITHUB_TOKEN to raise the limit.",
        )
    if response.status_code != 200:
        return _github_result(
            UNKNOWN, f"GitHub returned an unexpected status ({response.status_code})."
        )

    try:
        payload = response.json()
    except ValueError:
        logger.warning("GitHub user search returned a non-JSON body.")
        return _github_result(UNKNOWN, "The GitHub response could not be read.")

    if not isinstance(payload, dict):
        return _github_result(UNKNOWN, "The GitHub response could not be read.")

    raw_count = payload.get("total_count")
    raw_items = payload.get("items")
    # A well-formed empty result (total_count 0, items []) is a real "not found".
    # A body missing either field is a malformed response, and must not be
    # downgraded to an absence claim: see the Gravatar probe for the same rule.
    if not isinstance(raw_count, int) or not isinstance(raw_items, list):
        return _github_result(
            UNKNOWN, "The GitHub response was not in the expected format."
        )
    total_count = raw_count

    users = []
    for item in raw_items[:MAX_GITHUB_USERS]:
        if not isinstance(item, dict):
            continue
        users.append(
            {
                "login": _text(item.get("login")),
                "profile_url": _safe_url(item.get("html_url")),
                "avatar_url": _safe_url(item.get("avatar_url")),
            }
        )

    if not users and total_count <= 0:
        return _github_result(
            NOT_FOUND, "No GitHub account publicly lists this address.", total_count=0
        )
    return _github_result(
        FOUND,
        "At least one GitHub account publicly lists this address.",
        total_count=max(total_count, len(users)),
        users=users,
    )


def _summarise(probes: list[Signals]) -> Signals:
    """Roll the probe states up into counters a template can branch on."""
    states = [probe["state"] for probe in probes]
    unknown_count = states.count(UNKNOWN)
    return {
        "found_count": states.count(FOUND),
        "not_found_count": states.count(NOT_FOUND),
        "unknown_count": unknown_count,
        "any_found": FOUND in states,
        # True when at least one probe could not be completed, so the template
        # can warn that the report is incomplete rather than reassuring.
        "partial": unknown_count > 0,
    }


def gather_email_signals(email: object, client: HttpClient | None = None) -> Signals:
    """Gather public exposure signals for ``email``.

    Runs the three probes in sequence and returns their results. Probe failures
    are reported as ``unknown`` rather than raised, so this never crashes the
    page; only invalid *input* raises.

    Args:
        email: the address to probe. Trimmed, length-limited and lowercased
            before use.
        client: an optional HTTP client (see :class:`utils.http_client.
            HttpClient`; ``httpx.Client`` satisfies it). When omitted, one is
            created with
            explicit connect/read timeouts and closed before returning.
            Injecting a client is how the test suite avoids the network.

    Returns:
        A plain dict, safe to render directly. Every key below is always
        present, and every ``state`` is exactly one of ``"found"``,
        ``"not_found"`` or ``"unknown"``::

            {
              "email":         str,   # normalised address
              "email_redacted": str,  # e.g. "j***@example.com"
              "email_sha256":  str,   # the Gravatar lookup key
              "avatar": {
                "state":  str,
                "url":    str | None,   # renderable image URL when found
                "detail": str,          # human-readable reason/description
              },
              "profile": {
                "state":         str,
                "detail":        str,
                "profile_url":   str | None,   # validated http(s) or None
                "username":      str | None,
                "display_name":  str | None,
                "thumbnail_url": str | None,   # validated http(s) or None
                "location":      str | None,
                "job_title":     str | None,
                "company":       str | None,
                "pronouns":      str | None,
                "about_me":      str | None,
                "accounts": [            # linked social accounts, may be empty
                  {"domain": str | None, "display": str | None,
                   "shortname": str | None, "url": str | None},
                ],
                "emails": [str],         # other addresses on the profile
              },
              "github": {
                "state":       str,
                "detail":      str,
                "total_count": int,
                "users": [               # capped at MAX_GITHUB_USERS
                  {"login": str | None, "profile_url": str | None,
                   "avatar_url": str | None},
                ],
              },
              "summary": {
                "found_count": int, "not_found_count": int,
                "unknown_count": int, "any_found": bool, "partial": bool,
              },
            }

        Any ``*_url`` value is either a validated ``http``/``https`` URL or
        ``None``; a template may render it as an ``href`` without further
        checks, but must handle ``None``.

    Raises:
        ValueError: if ``email`` is empty or not plausibly an email address.
            Mirrors how :func:`scanner.find_footprint` rejects an empty query.
    """
    normalised = normalise_email(email)
    digest = email_digest(normalised)

    # INFO and above only ever sees the redacted form; the full address is PII.
    logger.info("Gathering email signals for %s", _redact(normalised))
    logger.debug("Email signal target: %s (sha256=%s)", normalised, digest)

    owns_client = client is None
    active = client if client is not None else _build_client()
    deadline = time.monotonic() + TOTAL_BUDGET_SECONDS
    skipped = "Skipped: the overall time budget for this scan was exhausted."

    try:
        avatar = _probe_avatar(active, digest)

        if time.monotonic() < deadline:
            profile = _probe_profile(active, digest)
        else:
            profile = _profile_result(UNKNOWN, skipped)

        if time.monotonic() < deadline:
            github = _probe_github(active, normalised)
        else:
            github = _github_result(UNKNOWN, skipped)
    finally:
        # Only close what we opened; an injected client belongs to the caller.
        if owns_client:
            active.close()

    return {
        "email": normalised,
        "email_redacted": _redact(normalised),
        "email_sha256": digest,
        "avatar": avatar,
        "profile": profile,
        "github": github,
        "summary": _summarise([avatar, profile, github]),
    }
