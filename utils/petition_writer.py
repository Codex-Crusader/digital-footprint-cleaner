"""Generate data-removal petitions for the URLs and sites a user selects.

A petition is assembled from three parts, so the wording can be tailored to the
site and to what is actually exposed rather than being one fixed paragraph:

* a **legal basis** (GDPR, CCPA/CPRA, India's DPDP Act, or a neutral request),
  which supplies the citation and the response deadline;
* the **data types** the user wants erased (address, phone, relatives, ...),
  which become the "specifically, I request the erasure of ..." sentence;
* the **target**, either a URL from the search results or a known data broker,
  which supplies the site name and any published opt-out URL.

The building blocks live in ``data/petition_templates.json`` so they can be
edited, translated, or extended without touching code. Substitution uses
:class:`string.Template` rather than :meth:`str.format`; ``format`` on a
data-file-supplied string allows attribute traversal (``{x.__class__}``), which
is not a risk worth carrying for zero benefit.

Two kinds of selections are supported by :func:`send_petitions`:

* Any ID the scan returned -- resolved to its URL through ``result_map``.
  Membership of that map is the test, deliberately: the scanner owns its ID
  format and this module must not encode a guess about it.
* ``broker_<id>`` -- an entry from the data-broker registry.
* Any other ID -- a curated service from the optional ``data/services.json``.

Everything degrades gracefully: if a data file is missing or malformed, a
built-in fallback template is used so petition generation never breaks.

This module generates correspondence from templates. It is not legal advice.
"""

import json
import logging
from datetime import date
from pathlib import Path
from string import Template
from typing import Any, Callable, Dict, List, Optional, Sequence

from utils.validation import (
    MAX_NAME_LENGTH,
    clamp_text,
    is_safe_http_url,
)

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_SERVICES_PATH = _DATA_DIR / "services.json"
_TEMPLATES_PATH = _DATA_DIR / "petition_templates.json"

DEFAULT_NAME = "The Requester"
DEFAULT_LEGAL_BASIS = "generic"
DEFAULT_DATA_TYPE = "full_profile"

# Used only when data/petition_templates.json is missing or unreadable. Keeps
# the feature working on a broken checkout instead of returning nothing.
_FALLBACK_BODY = (
    "To whom it may concern,\n\n"
    "I am writing to request the removal of my personal information from "
    "$site_name.\n\n"
    "$target_block"
    "Specifically, I request the erasure of $data_phrase.\n\n"
    "$legal_paragraph\n\n"
    "This request was submitted on $today. I look forward to your response "
    "within $response_days days.\n\n"
    "Sincerely,\n"
    "$user_name\n"
)
_FALLBACK_LEGAL_BASIS: Dict[str, Any] = {
    "id": "generic",
    "label": "General request",
    "applies_to": "",
    "response_days": 30,
    "paragraph": (
        "I make this request in accordance with applicable data protection "
        "and privacy regulations, and with your own published privacy policy."
    ),
}
_FALLBACK_DATA_TYPE: Dict[str, Any] = {
    "id": DEFAULT_DATA_TYPE,
    "label": "My entire listing / profile",
    "phrase": "my complete listing or profile in its entirety",
}


def _load_json(path: Any, description: str) -> Optional[Any]:
    """Read and parse a JSON file, returning None if it cannot be used."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read %s: %s", description, exc)
        return None


def _load_templates() -> Dict[str, Any]:
    """Load petition building blocks, falling back to built-in defaults."""
    data = _load_json(_TEMPLATES_PATH, "petition_templates.json")
    if not isinstance(data, dict):
        return {
            "body": _FALLBACK_BODY,
            "legal_bases": [_FALLBACK_LEGAL_BASIS],
            "data_types": [_FALLBACK_DATA_TYPE],
        }
    bases = [b for b in data.get("legal_bases", []) if isinstance(b, dict) and b.get("id")]
    types_ = [t for t in data.get("data_types", []) if isinstance(t, dict) and t.get("id")]
    body = data.get("body")
    return {
        "body": body if isinstance(body, str) and body.strip() else _FALLBACK_BODY,
        "legal_bases": bases or [_FALLBACK_LEGAL_BASIS],
        "data_types": types_ or [_FALLBACK_DATA_TYPE],
    }


# Loaded once at import; small, read-only, and shipped with the repo.
_TEMPLATES = _load_templates()
_LEGAL_BASES_BY_ID = {b["id"]: b for b in _TEMPLATES["legal_bases"]}
_DATA_TYPES_BY_ID = {t["id"]: t for t in _TEMPLATES["data_types"]}


def available_legal_bases() -> List[Dict[str, Any]]:
    """Return the selectable legal bases, for rendering a form."""
    return list(_TEMPLATES["legal_bases"])


def available_data_types() -> List[Dict[str, Any]]:
    """Return the selectable data types, for rendering a form."""
    return list(_TEMPLATES["data_types"])


def load_services() -> List[Any]:
    """Load curated service definitions.

    Returns an empty list if the optional ``data/services.json`` file is absent
    or malformed, so a missing data file never breaks petition generation.
    """
    data = _load_json(_SERVICES_PATH, "services.json")
    return data if isinstance(data, list) else []


def _join_phrases(phrases: Sequence[str]) -> str:
    """Join phrases into readable prose: 'a', 'a and b', 'a, b and c'."""
    items = [p for p in phrases if p]
    if not items:
        return _FALLBACK_DATA_TYPE["phrase"]
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _resolve_data_phrase(data_types: Optional[Sequence[Any]]) -> str:
    """Turn selected data-type IDs into the erasure sentence fragment.

    Unknown IDs are ignored rather than rendered literally, so a tampered form
    submission cannot inject arbitrary text into the petition body.

    Typed ``Sequence[Any]`` rather than ``Sequence[str]`` on purpose: these
    values arrive straight off an HTTP form, so a non-string is an input this
    function is documented to survive, not a mistake at the call site.
    """
    if not data_types:
        return _DATA_TYPES_BY_ID.get(DEFAULT_DATA_TYPE, _FALLBACK_DATA_TYPE)["phrase"]
    phrases = [
        _DATA_TYPES_BY_ID[t]["phrase"]
        for t in data_types
        if isinstance(t, str) and t in _DATA_TYPES_BY_ID
    ]
    return _join_phrases(phrases)


def _resolve_legal_basis(legal_basis: Optional[str]) -> Dict[str, Any]:
    """Look up a legal basis by ID, falling back to the neutral wording."""
    if isinstance(legal_basis, str) and legal_basis in _LEGAL_BASES_BY_ID:
        return _LEGAL_BASES_BY_ID[legal_basis]
    return _LEGAL_BASES_BY_ID.get(DEFAULT_LEGAL_BASIS, _FALLBACK_LEGAL_BASIS)


def build_petition(
    user_name: str = DEFAULT_NAME,
    url: Optional[str] = None,
    site_name: Optional[str] = None,
    opt_out_url: Optional[str] = None,
    data_types: Optional[Sequence[Any]] = None,
    legal_basis: Optional[str] = DEFAULT_LEGAL_BASIS,
) -> str:
    """Assemble a single petition.

    Args:
        user_name: the requester's name; trimmed, length-limited, and replaced
            with :data:`DEFAULT_NAME` when blank.
        url: the specific page hosting the data, if any. Only rendered when it
            is a safe http(s) URL.
        site_name: display name of the site. Defaults to a neutral phrase.
        opt_out_url: the site's published opt-out page, appended as a note when
            it is a safe http(s) URL.
        data_types: IDs from :func:`available_data_types`. Unknown IDs are
            dropped; an empty selection means the whole listing.
        legal_basis: an ID from :func:`available_legal_bases`. An unknown value
            falls back to the neutral request rather than raising, so a stale
            form never costs the user their petition.

    Returns:
        The petition body as plain text.
    """
    user_name = clamp_text(user_name, MAX_NAME_LENGTH) or DEFAULT_NAME
    basis = _resolve_legal_basis(legal_basis)

    target_block = ""
    if is_safe_http_url(url):
        target_block = f"The following page contains my personal data:\n\n    {url}\n\n"

    if is_safe_http_url(opt_out_url):
        target_block += (
            "I note that you publish an opt-out process at:\n\n"
            f"    {opt_out_url}\n\n"
            "This message serves as a formal request in addition to that process.\n\n"
        )

    response_days = basis.get("response_days", 30)
    try:
        response_days = int(response_days)
    except (TypeError, ValueError):
        response_days = 30

    template = Template(_TEMPLATES["body"])
    # safe_substitute: a missing placeholder must never raise mid-request.
    return template.safe_substitute(
        site_name=clamp_text(site_name, MAX_NAME_LENGTH) or "your organisation",
        target_block=target_block,
        data_phrase=_resolve_data_phrase(data_types),
        legal_paragraph=basis.get("paragraph", _FALLBACK_LEGAL_BASIS["paragraph"]),
        today=date.today().strftime("%B %d, %Y"),
        response_days=response_days,
        user_name=user_name,
    )


def send_petitions(
    selected_ids: Sequence[str],
    result_map: Any,
    user_name: str = DEFAULT_NAME,
    data_types: Optional[Sequence[Any]] = None,
    legal_basis: Optional[str] = DEFAULT_LEGAL_BASIS,
    broker_lookup: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
    broker_by_id: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
) -> List[Dict[str, str]]:
    """Generate petitions for the selected IDs.

    Three ID shapes are recognised:

    * any ID present in ``result_map`` -- a search result, resolved to its URL.
    * ``broker_<id>``  -- an entry from the data-broker registry, resolved by
      ``broker_by_id``. This is what the proactive opt-out checklist submits.
    * anything else    -- a curated entry in ``data/services.json``.

    Args:
        selected_ids: IDs chosen by the user.
        result_map: mapping of result ID -> URL, from the scan result store.
        user_name: the requester's name (trimmed and length-limited).
        data_types: IDs of the data categories to demand erasure of.
        legal_basis: ID of the legal basis to cite.
        broker_lookup: optional callable mapping a *URL* to a broker registry
            entry, used to address search-result petitions by broker name.
        broker_by_id: optional callable mapping a bare broker *ID* to its
            registry entry.

    Both lookups are injected rather than imported so this module keeps no
    dependency on ``analysis``; either may raise without losing the batch.

    Returns:
        A list of ``{"title", "text"}`` dicts, one per petition generated.
    """
    user_name = clamp_text(user_name, MAX_NAME_LENGTH) or DEFAULT_NAME
    services = load_services()
    petitions: List[Dict[str, str]] = []
    lookup_map = result_map if isinstance(result_map, dict) else {}

    for site_id in selected_ids:
        if not isinstance(site_id, str):
            continue

        # A search result is anything the scan actually returned, i.e. anything
        # present in result_map. This used to test for a "duck_" prefix, which
        # made the scanner's choice of ID format load-bearing in a module that
        # has no business knowing it: when the deep scan began emitting "deep_"
        # IDs, every petition for a search result silently stopped being
        # generated and the only trace was a warning in the log.
        if site_id in lookup_map:
            url = lookup_map.get(site_id)
            if not is_safe_http_url(url):
                # The URL is missing or was tampered with; skip it rather than
                # embedding untrusted content in the petition.
                logger.warning("Skipping %s: no valid URL in session map.", site_id)
                continue

            broker = None
            if broker_lookup is not None:
                try:
                    broker = broker_lookup(url)
                except Exception as exc:  # noqa: BLE001 - lookup must never break generation
                    logger.warning("Broker lookup failed for %s: %s", site_id, exc)

            if broker:
                site_name = broker.get("name")
                opt_out_url = broker.get("opt_out_url")
                title = f"Petition for {site_name}"
            else:
                site_name = None
                opt_out_url = None
                title = f"Search result ({site_id})"

            text = build_petition(
                user_name=user_name,
                url=url,
                site_name=site_name,
                opt_out_url=opt_out_url,
                data_types=data_types,
                legal_basis=legal_basis,
            )
        else:
            target: Optional[Dict[str, Any]] = None

            if site_id.startswith("broker_") and broker_by_id is not None:
                try:
                    target = broker_by_id(site_id[len("broker_"):])
                except Exception as exc:  # noqa: BLE001 - one bad lookup, not the batch
                    logger.warning("Broker lookup failed for %s: %s", site_id, exc)

            if target is None:
                target = next(
                    (s for s in services if isinstance(s, dict) and s.get("id") == site_id),
                    None,
                )

            if not target:
                logger.warning("Site ID '%s' matched no broker or service.", site_id)
                continue

            text = build_petition(
                user_name=user_name,
                url=target.get("url"),
                site_name=target.get("name"),
                opt_out_url=target.get("opt_out_url"),
                data_types=data_types,
                legal_basis=legal_basis,
            )
            title = f"Petition for {target.get('name', 'service')}"

        logger.info("Generated petition: %s", title)
        petitions.append({"title": title, "text": text})

    return petitions
