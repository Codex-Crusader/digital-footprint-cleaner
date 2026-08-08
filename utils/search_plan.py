"""Turning an :class:`~utils.identity.IdentityProfile` into a list of searches.

A single web search for a name is a shallow instrument. It returns whatever one
ranking algorithm considers the ten best pages for that string, which in
practice means a couple of social profiles and a lot of noise: and it
systematically misses the listings that matter most, because people-search and
directory pages rank poorly for bare names.

A *deep* search fixes that by asking several narrow questions instead of one
broad one, and this module decides what those questions are. Each
:class:`SearchPass` is one upstream request with a stated purpose, so the UI can
report exactly which parts of the sweep succeeded and which did not.

Two rules govern the plan:

**Queries stay high-recall.** Every term added to a query is an AND against a
full-text index. ``"Jane Doe" Austin Initech "Staff Engineer" 1985`` matches
nothing at all. The narrowing facts therefore never enter the query: they are
scored against the results afterwards (see :mod:`utils.identity`). Location is
the sole exception, because a city name genuinely improves retrieval for a
common name rather than destroying it, and even then it gets its own pass so a
bad location never suppresses the plain-name results.

**Site scoping is what makes it deep.** ``site:linkedin.com "Jane Doe"`` finds
the profile that a general search buries on page four. The cost is one request
per site against a backend that throttles, which is why the plan is tiered:
:data:`DEPTHS` lets the caller trade coverage against the odds of being rate
limited. This module is pure, it builds query strings and nothing else, so
the whole plan is unit-testable without touching the network.
"""

from dataclasses import dataclass
from typing import Iterable

from utils.identity import IdentityProfile

# Result counts per pass. Broad passes earn a bigger slice; a site-scoped pass
# rarely has more than a couple of genuine hits, and asking for more only adds
# noise and latency.
BROAD_PASS_RESULTS = 10
SCOPED_PASS_RESULTS = 4

# Platforms worth a dedicated site-scoped search, grouped by what a hit means.
# The tier number is the shallowest depth at which the group is included.
_SOCIAL_SITES = (
    ("linkedin.com", "LinkedIn", "professional"),
    ("facebook.com", "Facebook", "social_media"),
    ("instagram.com", "Instagram", "social_media"),
    ("x.com", "X / Twitter", "social_media"),
)
_EXTENDED_SITES = (
    ("github.com", "GitHub", "professional"),
    ("reddit.com", "Reddit", "forum"),
    ("youtube.com", "YouTube", "video"),
    ("tiktok.com", "TikTok", "social_media"),
    ("medium.com", "Medium", "professional"),
    ("about.me", "About.me", "professional"),
)

# Free-text passes aimed at record types that a bare name search does not
# surface. These use ordinary words rather than site scoping because the
# relevant sites are too numerous and too regional to enumerate.
_RECORD_PASSES = (
    ("records", "Public records", "public records", "public_records"),
    ("obituary", "Obituaries & family notices", "obituary OR genealogy", "public_records"),
    ("news", "News mentions", "news", "news_media"),
)


@dataclass(frozen=True)
class DepthPreset:
    """How much of the plan one depth tier builds.

    A dataclass rather than a dict of ``object``: the caps are read as numbers
    and the labels as strings, and a plain mapping forced every read through a
    cast that the type checker could not verify and a reader could not trust.
    """

    label: str
    description: str
    variants: int
    social: int
    extended: int
    records: int


# Depth presets. The labels are what the UI shows; the caps decide how much of
# the plan is built. More passes find more, and also make throttling more
# likely, which is an honest trade the user gets to make rather than one made
# for them.
DEPTHS: dict[str, DepthPreset] = {
    "quick": DepthPreset(
        label="Quick",
        description="Two broad searches. Fastest, least likely to be throttled.",
        variants=1,
        social=0,
        extended=0,
        records=0,
    ),
    "standard": DepthPreset(
        label="Standard",
        description="Broad searches plus the major social and professional sites.",
        variants=2,
        social=4,
        extended=0,
        records=1,
    ),
    "deep": DepthPreset(
        label="Deep",
        description="Every name spelling, ten platforms and public-record sweeps.",
        variants=3,
        social=4,
        extended=6,
        records=3,
    ),
}

DEFAULT_DEPTH = "standard"


@dataclass(frozen=True)
class SearchPass:
    """One upstream search, with enough context to explain it to the user.

    Attributes:
        key: unique, stable identifier for this pass within a plan.
        label: what the UI calls this pass in the coverage report.
        query: the exact string handed to the search backend.
        group: which section of the plan this belongs to, for grouped display.
        max_results: how many results to request.
        category_hint: the category a hit most likely belongs to. Used only as a
            fallback: :func:`analysis.classify` decides from the actual URL,
            which is authoritative. A site-scoped pass can still return a
            redirect or an off-site page.
    """

    key: str
    label: str
    query: str
    group: str
    max_results: int = BROAD_PASS_RESULTS
    category_hint: str = ""


def _quoted(name: str) -> str:
    """Wrap a name in quotes so the backend treats it as one phrase.

    Unquoted, ``Jane Doe`` matches pages containing "Jane" and "Doe" anywhere,
    so a different Jane and a different Doe on the same page score as a hit.
    Embedded quotes are stripped rather than escaped: the operator has no escape
    syntax, and a stray quote silently truncates the phrase.
    """
    return '"{}"'.format(name.replace('"', " ").strip())


def resolve_depth(depth: object) -> str:
    """Return a valid depth key, falling back to the default for anything else."""
    if isinstance(depth, str) and depth in DEPTHS:
        return depth
    return DEFAULT_DEPTH


def depth_choices() -> tuple[dict[str, str], ...]:
    """Depth presets in order, shaped for rendering as radio buttons."""
    return tuple(
        {
            "id": key,
            "label": DEPTHS[key].label,
            "description": DEPTHS[key].description,
        }
        for key in ("quick", "standard", "deep")
    )


def build_plan(profile: IdentityProfile, depth: str = DEFAULT_DEPTH) -> tuple[SearchPass, ...]:
    """Build the ordered list of searches to run for ``profile``.

    Order is significance-first, because the executor works down the list under
    a wall-clock budget and drops whatever it cannot reach. If the budget runs
    out, what gets skipped must be the least useful pass, not an arbitrary one.

    Returns an empty plan when there is no name to search for; the caller
    reports that as a validation error rather than running an empty sweep.
    """
    if not profile.has_name:
        return ()

    settings = DEPTHS[resolve_depth(depth)]

    variants = profile.name_variants()[: settings.variants] or (profile.full_name,)
    primary = _quoted(variants[0])
    # Site-scoped and record passes search the given+family spelling instead:
    # a scoped search is an exact match against one site's own index, so an
    # unlisted middle name turns a hit into a miss. See IdentityProfile.core_name.
    scoped_name = _quoted(profile.core_name or variants[0])
    passes: list[SearchPass] = []

    # 1. Name plus location. First because it is the single highest-value query
    #    for a common name: it is the one place a narrowing fact helps retrieval
    #    instead of hurting it.
    if profile.location:
        passes.append(
            SearchPass(
                key="name_location",
                label=f"Name and location ({profile.location})",
                query=f"{primary} {profile.location}",
                group="broad",
            )
        )

    # 2. The bare name, always. Runs even when a location was given, so a
    #    mistyped or wrong city cannot hide results that plainly exist.
    passes.append(
        SearchPass(
            key="name_exact",
            label="Exact name",
            query=primary,
            group="broad",
        )
    )

    # 3. Alternative spellings: "Doe, Jane" is how directories index people.
    for index, variant in enumerate(variants[1:], start=1):
        passes.append(
            SearchPass(
                key=f"name_variant_{index}",
                label=f"Name spelling: {variant}",
                query=_quoted(variant),
                group="broad",
            )
        )

    # 4. Site-scoped platform checks: the part a general search cannot do.
    scoped: Iterable[tuple[str, str, str]] = (
        list(_SOCIAL_SITES[: settings.social]) + list(_EXTENDED_SITES[: settings.extended])
    )
    for domain, label, category in scoped:
        passes.append(
            SearchPass(
                key=f"site_{domain.replace('.', '_')}",
                label=label,
                query=f"site:{domain} {scoped_name}",
                group="platforms",
                max_results=SCOPED_PASS_RESULTS,
                category_hint=category,
            )
        )

    # 5. Record-type sweeps, last: the widest net and the noisiest.
    for key, label, terms, category in _RECORD_PASSES[: settings.records]:
        passes.append(
            SearchPass(
                key=f"records_{key}",
                label=label,
                query=f"{scoped_name} {terms}",
                group="records",
                max_results=SCOPED_PASS_RESULTS,
                category_hint=category,
            )
        )

    return tuple(passes)


def plan_size(profile: IdentityProfile, depth: str = DEFAULT_DEPTH) -> int:
    """How many upstream requests a plan will make.

    Exists so the rate limiter can charge a deep scan what it actually costs.
    Deriving the figure from the plan, rather than hardcoding one, keeps the
    charge correct when the tiers above change, in the same way the username
    check derives its cost from the platform registry.
    """
    return len(build_plan(profile, depth))
