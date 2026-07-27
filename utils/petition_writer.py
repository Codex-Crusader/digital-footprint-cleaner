"""Generate data-removal petitions for the URLs a user selects.

Two kinds of selections are supported:

* ``duck_*`` IDs -- dynamic search results. A generic GDPR-style petition is
  produced from the URL stored in the session's ``result_map``.
* Any other ID -- a known service defined in ``data/services.json`` (optional).
  This branch is a hook for future curated templates; if the data file is
  missing it degrades gracefully instead of crashing.

``send_petitions`` returns the generated petitions so the web layer can show
them to the user, and also logs them for auditing/debugging.
"""

import json
import logging
from datetime import date
from pathlib import Path

from utils.validation import (
    MAX_NAME_LENGTH,
    clamp_text,
    is_safe_http_url,
)

logger = logging.getLogger(__name__)

_SERVICES_PATH = Path(__file__).resolve().parent.parent / "data" / "services.json"

DEFAULT_NAME = "The Requester"


def load_services():
    """Load curated service definitions.

    Returns an empty list if the optional ``data/services.json`` file is absent
    or malformed, so a missing data file never breaks petition generation.
    """
    try:
        with open(_SERVICES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read services.json: %s", exc)
        return []
    return data if isinstance(data, list) else []


def _generic_petition(url, user_name):
    """Build a generic removal petition for a single URL."""
    today = date.today().strftime("%B %d, %Y")
    return (
        "To whom it may concern,\n\n"
        "I am requesting the removal of the following URL that appears in "
        "search results for my name:\n\n"
        f"    URL: {url}\n\n"
        f"This request is submitted on {today}. Please process it in "
        "accordance with applicable privacy regulations.\n\n"
        "Sincerely,\n"
        f"{user_name}\n"
    )


def send_petitions(selected_ids, result_map, user_name=DEFAULT_NAME):
    """Generate petitions for the selected IDs.

    Args:
        selected_ids: IDs chosen by the user (``duck_*`` or curated service IDs).
        result_map: mapping of ``duck_*`` ID -> URL, taken from the session.
        user_name: the requester's name (trimmed and length-limited).

    Returns:
        A list of ``{"title", "text"}`` dicts, one per petition generated.
    """
    user_name = clamp_text(user_name, MAX_NAME_LENGTH) or DEFAULT_NAME
    services = load_services()
    petitions = []

    for site_id in selected_ids:
        if not isinstance(site_id, str):
            continue

        if site_id.startswith("duck_"):
            url = result_map.get(site_id)
            if not is_safe_http_url(url):
                # The URL is missing or was tampered with; skip it rather than
                # embedding untrusted content in the petition.
                logger.warning("Skipping %s: no valid URL in session map.", site_id)
                continue
            title = f"DuckDuckGo Result ({site_id})"
            text = _generic_petition(url, user_name)
        else:
            service = next((s for s in services if s.get("id") == site_id), None)
            if not service:
                logger.warning("Service ID '%s' not found in services.json.", site_id)
                continue
            template = service.get("petition_template", "")
            text = (
                template.format(
                    today=date.today().strftime("%B %d, %Y"),
                    site_name=service.get("name", "The Site"),
                )
                .replace("[Your Name]", user_name)
                .replace("[Your Full Name]", user_name)
            )
            title = f"Petition for {service.get('name', 'service')}"

        logger.info("Generated petition: %s", title)
        petitions.append({"title": title, "text": text})

    return petitions
