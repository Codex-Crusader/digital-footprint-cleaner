# scanner.py
"""Digital-footprint search backed by DuckDuckGo via the ``ddgs`` package.

Two public entry points:

* :func:`find_footprint` -- the broad scan. Validates the query, performs the
  search, and returns a list of *sanitised* result dictionaries. Results whose
  URL is not a plain ``http``/``https`` link are dropped so nothing unsafe is
  ever handed back to the template layer.
* :func:`check_brokers` (and :func:`check_broker`) -- targeted, site-scoped
  searches against known data brokers.

The second exists because of a real weakness in the first: a general web search
does not reliably rank people-search listing pages, so a broad scan often finds
nothing even when someone *is* listed. Running ``site:spokeo.com "Jane Doe"``
per broker finds those listings. The trade-off is one search per broker against
a backend that throttles, which is why the broker checks carry a concurrency
cap, an overall time budget, and a short-lived cache.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ddgs is declared in pyproject.toml and requirements.txt; see the note there
# about PyCharm not reading either in this project.
# noinspection PyPackageRequirements
from ddgs import DDGS

from utils.validation import (
    MAX_QUERY_LENGTH,
    clamp_text,
    is_safe_http_url,
)

logger = logging.getLogger(__name__)

# Cap the number of results we ask the search backend for. Keeps responses
# small and bounds the work done per request.
MAX_RESULTS = 10

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

    try:
        with DDGS() as ddgs:
            raw_results = list(ddgs.text(query=search_terms, max_results=MAX_RESULTS))
    except Exception as exc:  # noqa: BLE001 - normalise any backend failure
        # Log the exception *type* only. Backend exceptions frequently stringify
        # with the full request URL, which embeds the search terms -- i.e. the
        # user's name or email. Full detail stays at debug level.
        logger.warning("Search backend failed: %s", type(exc).__name__)
        logger.debug("Search backend failure detail", exc_info=True)
        raise SearchError("The search service is currently unavailable.") from exc

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
    """Cache a broker status. 'unknown' is not cached -- it is not an answer."""
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
        with DDGS() as ddgs:
            raw = list(
                ddgs.text(query=f'site:{domain} "{query}"', max_results=max_results)
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
    ``budget_seconds`` expires is reported as ``"unknown"`` -- a slow backend
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
