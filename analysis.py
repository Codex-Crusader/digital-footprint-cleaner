"""Footprint analysis: turn raw search results into an actionable exposure report.

This is what separates the tool from "just a web search": every result is
classified (data broker, social media, professional, public records, ...),
known people-search sites are flagged with their real opt-out URLs, and an
overall exposure risk is scored.

All functions here are pure and dependency-free (standard library only), so the
logic is fully unit-testable without any network access.
"""

import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

_BROKERS_PATH = Path(__file__).resolve().parent / "data" / "brokers.json"

# Category -> (display label, risk weight). Higher weight = more sensitive
# exposure. Data brokers dominate because they aggregate address/phone/relatives.
CATEGORY_META = {
    "data_broker": ("Data brokers & people-search", 20),
    "public_records": ("Public records", 12),
    "social_media": ("Social media", 6),
    "professional": ("Professional & dev", 3),
    "forum": ("Forums & Q&A", 3),
    "news_media": ("News & media", 2),
    "video": ("Video", 2),
    "reference": ("Reference", 1),
    "other": ("Other", 1),
}

# Suffix-matched domains for non-broker categories. Broker domains come from
# data/brokers.json and take precedence.
_DOMAIN_CATEGORY = {
    # social media
    "facebook.com": "social_media",
    "instagram.com": "social_media",
    "twitter.com": "social_media",
    "x.com": "social_media",
    "tiktok.com": "social_media",
    "snapchat.com": "social_media",
    "pinterest.com": "social_media",
    "tumblr.com": "social_media",
    "threads.net": "social_media",
    "mastodon.social": "social_media",
    "bsky.app": "social_media",
    # professional / developer
    "linkedin.com": "professional",
    "github.com": "professional",
    "gitlab.com": "professional",
    "stackoverflow.com": "professional",
    "medium.com": "professional",
    "behance.net": "professional",
    "dribbble.com": "professional",
    "crunchbase.com": "professional",
    "about.me": "professional",
    # forums / Q&A
    "reddit.com": "forum",
    "quora.com": "forum",
    "stackexchange.com": "forum",
    "ycombinator.com": "forum",
    # video
    "youtube.com": "video",
    "vimeo.com": "video",
    # reference
    "wikipedia.org": "reference",
    "wikidata.org": "reference",
    "britannica.com": "reference",
}


def _load_brokers():
    """Load the broker registry; return an empty list if unavailable."""
    try:
        with open(_BROKERS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    brokers = data.get("brokers", []) if isinstance(data, dict) else []
    return [b for b in brokers if isinstance(b, dict) and b.get("domain")]


# Loaded once at import; small and read-only.
BROKERS = _load_brokers()
_BROKER_BY_DOMAIN = {b["domain"].lower(): b for b in BROKERS}


def host_of(url):
    """Return the lowercased hostname without a leading 'www.'."""
    try:
        host = urlparse(url).netloc.lower()
    except (ValueError, AttributeError):
        return ""
    if host.startswith("www."):
        host = host[4:]
    # Drop any port suffix.
    return host.split(":")[0]


def _domain_matches(host, domain):
    """True if host is `domain` or a subdomain of it."""
    return host == domain or host.endswith("." + domain)


def broker_for(url):
    """Return the broker registry entry matching this URL, or None."""
    host = host_of(url)
    if not host:
        return None
    for domain, broker in _BROKER_BY_DOMAIN.items():
        if _domain_matches(host, domain):
            return broker
    return None


def classify(url):
    """Classify a URL into one of the CATEGORY_META categories."""
    host = host_of(url)
    if not host:
        return "other"
    broker = broker_for(url)
    if broker:
        return broker.get("category", "data_broker")
    for domain, category in _DOMAIN_CATEGORY.items():
        if _domain_matches(host, domain):
            return category
    if host.endswith(".gov"):
        return "public_records"
    return "other"


def _risk_level(broker_count, score):
    """Band the exposure. Broker presence dominates: brokers publish an
    individual's address/phone/relatives, so even one listing is meaningful,
    whereas a pile of benign mentions should never read as High on volume alone.
    """
    if broker_count >= 2:
        return "High"
    if broker_count == 1:
        return "High" if score >= 40 else "Medium"
    return "Medium" if score >= 15 else "Low"


def analyze(results):
    """Build an exposure report from a list of search-result dicts.

    Returns a dict with:
        categories: ordered list of {key, label, weight, items[]}
        brokers_found: list of {name, opt_out_url, url} confirmed in results
        score / risk_level: overall exposure
        total: number of results analysed
    """
    grouped = defaultdict(list)
    brokers_found = []
    seen_broker_ids = set()

    for result in results:
        url = result.get("url", "")
        category = classify(url)
        item = dict(result)
        item["category"] = category
        grouped[category].append(item)

        broker = broker_for(url)
        if broker and broker["id"] not in seen_broker_ids:
            seen_broker_ids.add(broker["id"])
            brokers_found.append(
                {
                    "name": broker["name"],
                    "opt_out_url": broker["opt_out_url"],
                    "url": url,
                }
            )

    score = sum(CATEGORY_META[cat][1] * len(items) for cat, items in grouped.items())
    score = min(score, 100)

    # Order categories by risk weight (most sensitive first).
    categories = [
        {
            "key": cat,
            "label": CATEGORY_META[cat][0],
            "weight": CATEGORY_META[cat][1],
            "results": items,
        }
        for cat, items in grouped.items()
    ]
    categories.sort(key=lambda c: c["weight"], reverse=True)

    return {
        "categories": categories,
        "brokers_found": brokers_found,
        "score": score,
        "risk_level": _risk_level(len(brokers_found), score),
        "total": len(results),
    }


def all_brokers():
    """Return the full curated broker registry (for the proactive checklist)."""
    return BROKERS
