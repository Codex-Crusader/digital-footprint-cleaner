"""Footprint analysis: turn raw search results into an actionable exposure report.

This is what separates the tool from "just a web search": every result is
classified (data broker, social media, professional, public records, ...),
known people-search sites are flagged with their real opt-out URLs, and an
overall exposure risk is scored.

All functions here are pure and dependency-free (standard library only), so the
logic is fully unit-testable without any network access.
"""

import json
import re
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlparse

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


# --- Match confidence --------------------------------------------------------
# Whether a result is *this* person, as opposed to a namesake.
#
# This is the half of the problem a search engine does not solve. Searching
# "James Smith" returns pages about hundreds of different James Smiths, and a
# privacy tool that presents them as one person's footprint is worse than
# useless -- it invites someone to file removal requests over a stranger's data,
# and it inflates their exposure score with records that were never theirs.
#
# The narrowing facts the user supplies are applied here rather than in the
# query (see utils.search_plan for why adding them to the query destroys
# recall): each result is checked for corroborating facts and banded.

CONFIDENCE_STRONG = "strong"
CONFIDENCE_LIKELY = "likely"
CONFIDENCE_POSSIBLE = "possible"
CONFIDENCE_UNVERIFIED = "unverified"

# Display metadata and sort order. Lower rank sorts first.
CONFIDENCE_META = {
    CONFIDENCE_STRONG: ("Strong match", 0),
    CONFIDENCE_LIKELY: ("Likely match", 1),
    CONFIDENCE_POSSIBLE: ("Possible match", 2),
    CONFIDENCE_UNVERIFIED: ("Name not found on page", 3),
}

# Summed factor weight needed for each band. Two independent facts (say a city
# at weight 3 and an employer at weight 4) clear STRONG; one on its own reaches
# LIKELY. The weights come from utils.identity.
_STRONG_THRESHOLD = 7
_LIKELY_THRESHOLD = 3

# How much a result counts toward the exposure score, by band. A page that never
# mentions the name is search drift and contributes nothing; without a profile
# to check against, every result stays at 1.0 and scoring is unchanged.
_CONFIDENCE_WEIGHT = {
    CONFIDENCE_STRONG: 1.0,
    CONFIDENCE_LIKELY: 1.0,
    CONFIDENCE_POSSIBLE: 1.0,
    CONFIDENCE_UNVERIFIED: 0.0,
}


def _haystack(result):
    """Flatten a result into one searchable string.

    The URL is included twice over: once verbatim, and once with its separators
    turned into spaces. Identifying facts are frequently in the path rather than
    the text -- ``/Jane-Doe/TX/Austin`` names a city that appears nowhere in the
    title or snippet -- but the word-boundary patterns in
    :mod:`utils.identity` cannot see through a hyphen.
    """
    url = result.get("url", "") or ""
    try:
        readable = unquote(url)
    except (ValueError, TypeError):
        readable = url
    spaced = re.sub(r"[-_+/.,:?&=#%]+", " ", readable)
    return " ".join(
        (
            str(result.get("title", "") or ""),
            str(result.get("snippet", "") or ""),
            readable,
            spaced,
        )
    )


def score_match(result, profile):
    """Judge whether ``result`` belongs to ``profile``'s subject.

    Returns ``(confidence, matched_factors)`` where ``matched_factors`` is a
    list of ``{"key", "label", "value"}`` describing what corroborated it, so
    the UI can show *why* a result was ranked highly instead of asking the user
    to trust a badge.

    Name presence acts as a floor, not a bonus. A page that names neither the
    full name nor the surname is ranked ``unverified`` no matter how many other
    facts happen to appear on it -- on a page about a company, the employer and
    city will both match while the person is entirely absent.
    """
    if profile is None or not profile.has_name:
        return CONFIDENCE_POSSIBLE, []

    haystack = _haystack(result)

    name_patterns = profile.surname_patterns()
    if name_patterns and not any(p.search(haystack) for p in name_patterns):
        return CONFIDENCE_UNVERIFIED, []

    matched = []
    weight = 0
    for factor in profile.factors():
        if factor.matches(haystack):
            matched.append({"key": factor.key, "label": factor.label, "value": factor.value})
            weight += factor.weight

    if weight >= _STRONG_THRESHOLD:
        return CONFIDENCE_STRONG, matched
    if weight >= _LIKELY_THRESHOLD:
        return CONFIDENCE_LIKELY, matched
    return CONFIDENCE_POSSIBLE, matched


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


def analyze(results, profile=None):
    """Build an exposure report from a list of search-result dicts.

    Args:
        results: sanitised result dicts from the scanner.
        profile: optional :class:`~utils.identity.IdentityProfile`. When given,
            every result is scored for whether it is actually this person and
            the report gains a confidence breakdown. When omitted, behaviour is
            exactly as before -- the tool stays fully usable for someone who
            supplies nothing but a name.

    Returns a dict with:
        categories: ordered list of {key, label, weight, results[]}
        brokers_found: list of {name, opt_out_url, url} confirmed in results
        score / risk_level: overall exposure
        total: number of results analysed
        confidence_counts: how many results landed in each band
        unverified: results whose page never names the subject, split out so
            they can be shown separately rather than deleted -- a name absent
            from the snippet is sometimes present on the page itself.
    """
    grouped = defaultdict(list)
    brokers_found = []
    seen_broker_ids = set()
    confidence_counts: "defaultdict[str, int]" = defaultdict(int)
    unverified = []
    score_total = 0.0

    for result in results:
        url = result.get("url", "")
        category = classify(url)
        item = dict(result)
        item["category"] = category
        item["category_label"] = CATEGORY_META[category][0]

        confidence, matched = score_match(result, profile)
        item["confidence"] = confidence
        item["confidence_label"] = CONFIDENCE_META[confidence][0]
        item["matched_factors"] = matched
        confidence_counts[confidence] += 1

        score_total += CATEGORY_META[category][1] * _CONFIDENCE_WEIGHT[confidence]

        if confidence == CONFIDENCE_UNVERIFIED:
            # Kept out of the categories so the main report stays trustworthy,
            # but never silently dropped -- see the docstring.
            unverified.append(item)
            continue

        grouped[category].append(item)

        broker = broker_for(url)
        if broker and broker["id"] not in seen_broker_ids:
            seen_broker_ids.add(broker["id"])
            brokers_found.append(
                {
                    "name": broker["name"],
                    "opt_out_url": broker["opt_out_url"],
                    "url": url,
                    "confidence": confidence,
                    "confidence_label": CONFIDENCE_META[confidence][0],
                }
            )

    score = min(int(round(score_total)), 100)

    # Within a category, put the results most likely to be the right person
    # first; a strong match buried under six namesakes helps nobody.
    for items in grouped.values():
        items.sort(key=lambda r: CONFIDENCE_META[r["confidence"]][1])

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
        "confidence_counts": dict(confidence_counts),
        "unverified": unverified,
        "profiled": bool(profile is not None and profile.factors()),
    }


def all_brokers():
    """Return the full curated broker registry (for the proactive checklist)."""
    return BROKERS
