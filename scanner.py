# scanner.py
"""Digital-footprint search backed by DuckDuckGo via the ``ddgs`` package.

The public entry point is :func:`find_footprint`. It validates the query,
performs the search, and returns a list of *sanitised* result dictionaries.
Results whose URL is not a plain ``http``/``https`` link are dropped so nothing
unsafe is ever handed back to the template layer.
"""

import logging

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
        # Do not leak the raw query into the exception message that may surface
        # to users; log it at debug level only.
        logger.warning("Search backend failed: %s", exc)
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
