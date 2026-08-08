# scanner.py
"""Digital-footprint search backed by DuckDuckGo via the ``ddgs`` package.

Two public entry points:

* :func:`find_footprint`: the broad scan. Validates the query, performs the
  search, and returns a list of *sanitised* result dictionaries. Results whose
  URL is not a plain ``http``/``https`` link are dropped so nothing unsafe is
  ever handed back to the template layer.
* :func:`check_brokers` (and :func:`check_broker`): targeted, site-scoped
  searches against known data brokers.

The second exists because of a real weakness in the first: a general web search
does not reliably rank people-search listing pages, so a broad scan often finds
nothing even when someone *is* listed. Running ``site:spokeo.com "Jane Doe"``
per broker finds those listings. The trade-off is one search per broker against
a backend that throttles, which is why the broker checks carry a concurrency
cap, an overall time budget, and a short-lived cache.
"""

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

# ddgs is declared in pyproject.toml and requirements.txt; see the note there
# about PyCharm not reading either in this project.
# noinspection PyPackageRequirements
from ddgs import DDGS

from utils.identity import IdentityProfile
from utils.search_plan import DEFAULT_DEPTH, SearchPass, build_plan
from utils.validation import (
    MAX_QUERY_LENGTH,
    clamp_text,
    is_safe_http_url,
)

logger = logging.getLogger(__name__)

# Cap the number of results we ask the search backend for. Keeps responses
# small and bounds the work done per request.
MAX_RESULTS = 10

# How long a single ungrouped search may spend waiting for a slot at the gate.
# Generous, because there is only one request to make; a deep scan sets its own,
# much tighter, per-pass share of the overall budget.
SINGLE_SEARCH_BUDGET_SECONDS = 20.0

# --- Global rate governor ----------------------------------------------------
# Every upstream search in this module: deep-scan pass, broker check, plain
# scan: passes through one gate before it is issued.
#
# This is the mechanism that keeps "search deeper" from turning into "show more
# errors". The two goals are in direct tension: more passes means more requests
# means a higher chance DuckDuckGo throttles the lot, and a throttled batch
# returns *worse* data than a smaller patient one. A per-call retry loop makes
# it worse still, because each caller independently decides to try again at
# exactly the moment the backend is asking everyone to slow down.
#
# One shared gate fixes that. It enforces a minimum interval between request
# starts and a ceiling on concurrency, and, crucially, it widens that
# interval automatically when the backend signals throttling, then narrows it
# again as requests start succeeding. Callers do not opt in or coordinate; they
# cannot, because the whole point is that the limit is global.
SEARCH_MIN_INTERVAL = float(os.getenv("SEARCH_MIN_INTERVAL", "0.35"))  # seconds
SEARCH_MAX_CONCURRENCY = int(os.getenv("SEARCH_MAX_CONCURRENCY", "3"))
# How far the gate is allowed to widen under sustained throttling, and how
# sharply it reacts. Backing off to ~2s between requests is slow but still
# finishes a plan inside the budget; beyond that it is better to report the
# passes as incomplete than to keep the user waiting.
SEARCH_MAX_INTERVAL = 2.0
_BACKOFF_FACTOR = 2.0
_RECOVERY_FACTOR = 0.7

_gate_lock = threading.Lock()
_gate_semaphore = threading.BoundedSemaphore(max(1, SEARCH_MAX_CONCURRENCY))
_gate_next_at = 0.0
_gate_interval = SEARCH_MIN_INTERVAL

# Exception names that mean "you are asking too often" rather than "something
# broke". Matched by class name so no ddgs internals need importing; the package
# has renamed and moved this exception more than once.
_THROTTLE_MARKERS = ("ratelimit", "toomany", "429", "timeout")


def _looks_throttled(exc: BaseException) -> bool:
    """True if ``exc`` indicates rate limiting rather than a hard failure."""
    name = type(exc).__name__.lower().replace("_", "")
    if any(marker in name for marker in _THROTTLE_MARKERS):
        return True
    # Fall back to the message for backends that raise a generic error. Only the
    # status code is checked, never the full text, which can embed the query.
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "too many requests" in text


def _note_throttled() -> None:
    """Widen the shared gate after a throttling signal."""
    global _gate_interval
    with _gate_lock:
        _gate_interval = min(SEARCH_MAX_INTERVAL, max(_gate_interval, 0.05) * _BACKOFF_FACTOR)
        logger.info("Search gate widened to %.2fs after throttling.", _gate_interval)


def _note_success() -> None:
    """Narrow the shared gate back toward its baseline after a clean request."""
    global _gate_interval
    with _gate_lock:
        if _gate_interval > SEARCH_MIN_INTERVAL:
            _gate_interval = max(SEARCH_MIN_INTERVAL, _gate_interval * _RECOVERY_FACTOR)


def _acquire_slot(deadline: float) -> bool:
    """Wait for permission to issue one upstream search.

    Returns ``False``, without sleeping out the remaining time, when the
    wait would push past ``deadline``. That is what lets a plan degrade into
    "these passes ran, these were skipped" instead of hanging: a caller that
    cannot get a slot in time reports the pass as skipped and moves on.

    ``deadline`` is a :func:`time.monotonic` timestamp. It must be finite:
    ``Semaphore.acquire`` rejects an infinite timeout, and every caller has a
    budget to respect anyway.
    """
    global _gate_next_at
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    if not _gate_semaphore.acquire(timeout=remaining):
        return False

    with _gate_lock:
        now = time.monotonic()
        start_at = max(now, _gate_next_at)
        if start_at > deadline:
            _gate_semaphore.release()
            return False
        _gate_next_at = start_at + _gate_interval

    wait = start_at - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    return True


def _release_slot() -> None:
    """Return a slot taken by :func:`_acquire_slot`."""
    try:
        _gate_semaphore.release()
    except ValueError:  # pragma: no cover - only reachable on unbalanced use
        logger.warning("Search gate released more times than acquired.")


def reset_governor(interval: float | None = None) -> None:
    """Reset the shared gate. Public hook used by tests.

    Tests pass ``interval=0`` so a fake backend runs at full speed; leaving the
    real pacing in place would add seconds to the suite for no coverage.
    """
    global _gate_next_at, _gate_interval, _gate_semaphore
    with _gate_lock:
        _gate_next_at = 0.0
        _gate_interval = SEARCH_MIN_INTERVAL if interval is None else max(0.0, interval)
    _gate_semaphore = threading.BoundedSemaphore(max(1, SEARCH_MAX_CONCURRENCY))


def _run_search(query: str, max_results: int, deadline: float) -> list[dict]:
    """Issue one governed search and return its raw results.

    Raises:
        SearchError: the gate could not be entered before ``deadline``, or the
            backend failed. The two are distinguished by the message so the
            caller can label a pass "skipped" rather than "failed".
    """
    if not _acquire_slot(deadline):
        raise SearchError("skipped: no capacity within the time budget")
    try:
        with DDGS() as ddgs:
            raw = list(ddgs.text(query=query, max_results=max_results))
    except Exception as exc:  # noqa: BLE001 - normalise any backend failure
        # Log the exception *type* only. Backend exceptions frequently stringify
        # with the full request URL, which embeds the search terms: i.e. the
        # user's name or email. Full detail stays at debug level.
        if _looks_throttled(exc):
            _note_throttled()
            logger.warning("Search throttled by backend: %s", type(exc).__name__)
            raise SearchError("throttled by the search backend") from exc
        logger.warning("Search backend failed: %s", type(exc).__name__)
        logger.debug("Search backend failure detail", exc_info=True)
        raise SearchError("The search service is currently unavailable.") from exc
    else:
        _note_success()
        return raw
    finally:
        _release_slot()


# --- Site-scoped broker checks ----------------------------------------------
# Tuning for check_brokers(). DuckDuckGo rate-limits aggressively, so the
# concurrency here is deliberately low: firing 30 parallel searches gets the
# whole batch throttled and returns worse data than 3 patient ones.
BROKER_CHECK_WORKERS = 3
BROKER_CHECK_BUDGET_SECONDS = 25.0
BROKER_CHECK_MAX = 8
BROKER_CHECK_RESULTS = 5
_BROKER_CACHE_TTL_SECONDS = 900.0

_broker_cache: "dict[tuple[str, str], tuple[float, str]]" = {}
_broker_cache_lock = threading.Lock()


class SearchError(RuntimeError):
    """Raised when the search backend is unavailable or rejects the request.

    This is distinct from *"the search succeeded but found nothing"*, which is
    represented by an empty result list.
    """


def find_footprint(query, location=None):
    """Search DuckDuckGo for ``query`` and return sanitised result dicts.

    Each returned item is ``{"id", "title", "url", "snippet"}``. Only results
    with a safe ``http``/``https`` URL are included. Returns an empty list when
    the search genuinely finds nothing.

    Args:
        query: the name or email to search for.
        location: optional city/state to disambiguate common names; appended to
            the search query when provided.

    Raises:
        ValueError: if ``query`` is empty after trimming.
        SearchError: if the search backend fails (e.g. network error, rate
            limiting by DuckDuckGo).
    """
    query = clamp_text(query, MAX_QUERY_LENGTH)
    if not query:
        raise ValueError("Search query must not be empty.")

    location = clamp_text(location or "", MAX_QUERY_LENGTH)
    search_terms = f"{query} {location}".strip() if location else query

    # Routed through the shared gate like every other upstream search, so a
    # plain scan run straight after a deep sweep waits its turn rather than
    # arriving while the backend is already throttling this process.
    raw_results = _run_search(
        search_terms, MAX_RESULTS, time.monotonic() + SINGLE_SEARCH_BUDGET_SECONDS
    )

    results = []
    for i, result in enumerate(raw_results):
        url = result.get("href", "")
        if not is_safe_http_url(url):
            # Skip anything that is not a plain web link (e.g. javascript: URIs).
            continue
        results.append(
            {
                "id": f"duck_{i}",  # stable, unique ID used by the /send form
                "title": result.get("title") or "Untitled result",
                "url": url.strip(),
                "snippet": result.get("body", ""),
            }
        )
    return results


# --- Site-scoped broker checks ----------------------------------------------
# These helpers duplicate a few lines of analysis.host_of on purpose: `scanner`
# acquires data and `analysis` interprets it, so importing upwards would invert
# the layering for four lines of URL parsing.


def _result_host(url):
    """Return the lowercased hostname of ``url`` without 'www.' or a port."""
    try:
        host = urlparse(url).netloc.lower()
    except (ValueError, AttributeError):
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host.split(":")[0]


def _host_is_on_domain(host, domain):
    """True if ``host`` is ``domain`` or a subdomain of it."""
    return bool(host) and (host == domain or host.endswith("." + domain))


def _cached_status(cache_key):
    """Return a cached broker status if it is still fresh, else None."""
    with _broker_cache_lock:
        entry = _broker_cache.get(cache_key)
        if not entry:
            return None
        stored_at, status = entry
        if time.time() - stored_at > _BROKER_CACHE_TTL_SECONDS:
            _broker_cache.pop(cache_key, None)
            return None
        return status


def _store_status(cache_key, status):
    """Cache a broker status. 'unknown' is not cached: it is not an answer."""
    if status == "unknown":
        return
    with _broker_cache_lock:
        _broker_cache[cache_key] = (time.time(), status)


def reset_broker_cache():
    """Clear the broker-check cache. Public hook used by tests."""
    with _broker_cache_lock:
        _broker_cache.clear()


def check_broker(query, domain, max_results=BROKER_CHECK_RESULTS):
    """Run one ``site:<domain> "<query>"`` search and report what it found.

    Args:
        query: the name to look for, already user-supplied and unvalidated.
        domain: the broker domain to scope the search to, e.g. ``spokeo.com``.
        max_results: how many results to request from the backend.

    Returns:
        One of ``"listed"`` (a page on that domain matched), ``"not_listed"``
        (the search ran and returned nothing on that domain), or ``"unknown"``
        (the search failed or was throttled).

        ``"unknown"`` is deliberately distinct from ``"not_listed"``: telling
        someone they are absent from a broker when the check merely failed is
        the most damaging thing a privacy tool can get wrong.
    """
    query = clamp_text(query, MAX_QUERY_LENGTH)
    domain = clamp_text(domain, MAX_QUERY_LENGTH).lower()
    if not query or not domain:
        return "unknown"

    cache_key = (query.lower(), domain)
    cached = _cached_status(cache_key)
    if cached is not None:
        return cached

    try:
        raw = _run_search(
            f'site:{domain} "{query}"',
            max_results,
            time.monotonic() + BROKER_CHECK_BUDGET_SECONDS,
        )
    except Exception as exc:  # noqa: BLE001 - throttling and network errors alike
        # Type only: the exception text can carry the scoped query, and the
        # query contains the name being searched for.
        logger.warning("Broker check failed for %s: %s", domain, type(exc).__name__)
        logger.debug("Broker check failure detail for %s", domain, exc_info=True)
        return "unknown"

    for result in raw:
        url = result.get("href", "")
        # A result only counts if it is a safe link actually hosted on the
        # broker's domain. Search engines happily return third-party pages that
        # merely mention the site, which would produce false "you are listed".
        if is_safe_http_url(url) and _host_is_on_domain(_result_host(url), domain):
            _store_status(cache_key, "listed")
            return "listed"

    _store_status(cache_key, "not_listed")
    return "not_listed"


def check_brokers(
    query,
    brokers,
    max_checks=BROKER_CHECK_MAX,
    budget_seconds=BROKER_CHECK_BUDGET_SECONDS,
    workers=BROKER_CHECK_WORKERS,
):
    """Check ``query`` against several brokers with a hard time budget.

    This is the direct answer to the project's headline limitation: a general
    web search rarely surfaces broker listing pages, so scoping one search per
    broker finds listings the main scan misses.

    Only the first ``max_checks`` brokers are attempted. The rest come back as
    ``"skipped"`` rather than being silently dropped, so the UI can say plainly
    how much of the list was actually covered. Any broker still in flight when
    ``budget_seconds`` expires is reported as ``"unknown"``: a slow backend
    must never hold a web request open indefinitely.

    Honest caveat about the deadline: it bounds how long the *caller* waits, not
    how long the work runs. ``cancel_futures`` only cancels futures still queued,
    so up to ``workers`` already-running searches keep going in the background
    after this returns. They do not hold the Flask worker, but repeated sweeps
    against a hung backend can accumulate detached threads.

    Args:
        query: the name to look for.
        brokers: broker registry entries (dicts with ``id``/``name``/``domain``).
        max_checks: maximum number of brokers to actually search.
        budget_seconds: overall wall-clock budget for the whole batch.
        workers: thread-pool size. Kept small on purpose; DuckDuckGo throttles
            parallel bursts, so more workers returns *less* data, not more.

    Returns:
        A list of ``{"id", "name", "domain", "opt_out_url", "status"}`` dicts in
        the order given, where status is listed / not_listed / unknown / skipped.
    """
    query = clamp_text(query, MAX_QUERY_LENGTH)
    entries = [b for b in (brokers or []) if isinstance(b, dict) and b.get("domain")]
    if not query:
        raise ValueError("Search query must not be empty.")

    def _entry(registry_entry, status):
        return {
            "id": registry_entry.get("id", ""),
            "name": registry_entry.get("name", registry_entry.get("domain", "")),
            "domain": registry_entry.get("domain", ""),
            "opt_out_url": registry_entry.get("opt_out_url", ""),
            "status": status,
        }

    to_check = entries[:max_checks]
    statuses = {id(b): "skipped" for b in entries}

    if to_check:
        deadline = time.monotonic() + budget_seconds
        executor = ThreadPoolExecutor(max_workers=max(1, workers))
        try:
            futures = {
                executor.submit(check_broker, query, b["domain"]): b for b in to_check
            }
            for future in as_completed(futures, timeout=max(0.0, budget_seconds)):
                broker = futures[future]
                try:
                    statuses[id(broker)] = future.result()
                except Exception as exc:  # noqa: BLE001 - isolate one bad broker
                    logger.warning("Broker check errored: %s", exc)
                    statuses[id(broker)] = "unknown"
                if time.monotonic() >= deadline:
                    break
        except TimeoutError:
            logger.warning("Broker check batch exceeded its %.0fs budget.", budget_seconds)
        finally:
            # Anything unfinished stays 'unknown'; never block the request on it.
            executor.shutdown(wait=False, cancel_futures=True)

        for broker in to_check:
            if statuses[id(broker)] == "skipped":
                statuses[id(broker)] = "unknown"

    return [_entry(b, statuses[id(b)]) for b in entries]


# --- Deep multi-pass scan ----------------------------------------------------
# The plain scan asks the web one question. The deep scan asks several narrow
# ones (see utils.search_plan) and merges the answers, which is what surfaces
# the profile pages and directory listings a single query never ranks.

DEEP_SEARCH_BUDGET_SECONDS = float(os.getenv("DEEP_SEARCH_BUDGET", "40"))
DEEP_SEARCH_WORKERS = 3
# Cap on merged results. A deep plan can legitimately return well over a
# hundred; past this point the page becomes unreadable and the tail is noise.
DEEP_SEARCH_MAX_RESULTS = 120

PASS_OK = "ok"
PASS_EMPTY = "empty"
PASS_FAILED = "failed"
PASS_SKIPPED = "skipped"


@dataclass(frozen=True)
class PassOutcome:
    """What happened to one search pass, in terms the UI can show verbatim.

    ``failed`` and ``empty`` are kept strictly apart, for the same reason
    :func:`check_broker` separates ``unknown`` from ``not_listed``: presenting a
    pass that never ran as a pass that found nothing tells the user they are
    clean when nobody actually looked.
    """

    key: str
    label: str
    group: str
    status: str
    count: int = 0
    detail: str = ""

    @property
    def ran(self) -> bool:
        """True if the pass reached the backend, whatever it came back with."""
        return self.status in (PASS_OK, PASS_EMPTY)


@dataclass
class DeepSearchReport:
    """Merged results of a deep scan plus an honest account of its coverage."""

    results: list[dict] = field(default_factory=list)
    outcomes: list[PassOutcome] = field(default_factory=list)

    @property
    def total_passes(self) -> int:
        return len(self.outcomes)

    @property
    def completed_passes(self) -> int:
        return sum(1 for o in self.outcomes if o.ran)

    @property
    def failed_passes(self) -> int:
        return sum(1 for o in self.outcomes if not o.ran)

    @property
    def partial(self) -> bool:
        """True when some pass did not complete, so coverage is incomplete."""
        return self.failed_passes > 0

    @property
    def complete(self) -> bool:
        return self.total_passes > 0 and not self.partial


def _dedupe_key(url: str) -> str:
    """Canonical form of ``url`` for spotting the same page found twice.

    Different passes routinely return the same page with a different fragment
    or a stray trailing slash. Without this, one profile shows up four times and
    the exposure score counts it four times.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return url.lower()
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path.rstrip("/") or "/"
    # The fragment never identifies a different page; the query sometimes does
    # (listing IDs live there), so it is preserved.
    return urlunparse(("", host, path, "", parsed.query, ""))


def _run_pass(search_pass: SearchPass, deadline: float) -> tuple[PassOutcome, list[dict]]:
    """Execute one pass and describe the outcome. Never raises."""
    try:
        raw = _run_search(search_pass.query, search_pass.max_results, deadline)
    except SearchError as exc:
        skipped = str(exc).startswith("skipped:")
        return (
            PassOutcome(
                key=search_pass.key,
                label=search_pass.label,
                group=search_pass.group,
                status=PASS_SKIPPED if skipped else PASS_FAILED,
                detail=(
                    "Not attempted: the scan ran out of time."
                    if skipped
                    else "The search service did not answer this one."
                ),
            ),
            [],
        )
    except Exception as exc:  # noqa: BLE001 - one bad pass must not kill the scan
        logger.warning("Search pass %s errored: %s", search_pass.key, type(exc).__name__)
        return (
            PassOutcome(
                key=search_pass.key,
                label=search_pass.label,
                group=search_pass.group,
                status=PASS_FAILED,
                detail="This check could not be completed.",
            ),
            [],
        )

    items = []
    for result in raw:
        url = result.get("href", "")
        if not is_safe_http_url(url):
            # Skip anything that is not a plain web link (e.g. javascript: URIs).
            continue
        items.append(
            {
                "title": result.get("title") or "Untitled result",
                "url": url.strip(),
                "snippet": result.get("body", ""),
                "pass_key": search_pass.key,
                "pass_label": search_pass.label,
                "category_hint": search_pass.category_hint,
            }
        )

    return (
        PassOutcome(
            key=search_pass.key,
            label=search_pass.label,
            group=search_pass.group,
            status=PASS_OK if items else PASS_EMPTY,
            count=len(items),
            detail="" if items else "Ran successfully; nothing found here.",
        ),
        items,
    )


def deep_search(
    profile: IdentityProfile,
    depth: str = DEFAULT_DEPTH,
    budget_seconds: float = DEEP_SEARCH_BUDGET_SECONDS,
    workers: int = DEEP_SEARCH_WORKERS,
) -> DeepSearchReport:
    """Run the whole search plan for ``profile`` and merge what comes back.

    Never raises for a backend problem. A deep scan makes many requests and some
    of them *will* fail: that is the normal case, not the exceptional one. An
    exception would throw away the passes that did succeed, so failures are
    recorded per pass in :attr:`DeepSearchReport.outcomes` and the caller shows
    coverage alongside results.

    The whole plan shares one wall-clock budget. Passes are submitted in plan
    order, which is significance-first, so if the budget runs out it is the
    least valuable passes that go unrun.

    Raises:
        ValueError: if ``profile`` has no name to search for. That is a
            validation error in the caller, not a search failure.
    """
    plan = build_plan(profile, depth)
    if not plan:
        raise ValueError("Search profile must include a name.")

    deadline = time.monotonic() + max(1.0, budget_seconds)
    outcomes: dict[str, PassOutcome] = {}
    collected: list[dict] = []

    executor = ThreadPoolExecutor(max_workers=max(1, workers))
    try:
        futures = {executor.submit(_run_pass, p, deadline): p for p in plan}
        try:
            for future in as_completed(futures, timeout=max(0.1, budget_seconds)):
                outcome, items = future.result()
                outcomes[outcome.key] = outcome
                collected.extend(items)
        except TimeoutError:
            logger.warning("Deep scan exceeded its %.0fs budget.", budget_seconds)
    finally:
        # Same caveat as check_brokers: already-running searches keep going
        # briefly after this returns. They cannot outlive the deadline by much,
        # because the gate refuses new slots past it.
        executor.shutdown(wait=False, cancel_futures=True)

    # Merge, preserving plan order so the most significant passes' results lead.
    order = {p.key: index for index, p in enumerate(plan)}
    collected.sort(key=lambda item: order.get(item["pass_key"], len(order)))

    merged: dict[str, dict] = {}
    for item in collected:
        key = _dedupe_key(item["url"])
        existing = merged.get(key)
        if existing is None:
            item = dict(item)
            # A page several independent passes turn up is more likely to be a
            # genuine hit than a one-off, so the count is kept for scoring.
            item["found_by"] = [item["pass_label"]]
            merged[key] = item
        elif item["pass_label"] not in existing["found_by"]:
            existing["found_by"].append(item["pass_label"])

    results = list(merged.values())[:DEEP_SEARCH_MAX_RESULTS]
    for index, item in enumerate(results):
        item["id"] = f"deep_{index}"

    report = DeepSearchReport(results=results)
    report.outcomes = [
        outcomes.get(
            p.key,
            PassOutcome(
                key=p.key,
                label=p.label,
                group=p.group,
                status=PASS_SKIPPED,
                detail="Not attempted: the scan ran out of time.",
            ),
        )
        for p in plan
    ]
    return report
