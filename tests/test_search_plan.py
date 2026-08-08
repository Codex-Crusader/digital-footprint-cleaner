"""Tests for the deep-search query plan.

The plan is where recall is won or lost, so most of these assert what must
*not* end up in a query as firmly as what must.
"""

# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

from utils.identity import IdentityProfile
from utils.search_plan import (
    DEFAULT_DEPTH,
    build_plan,
    depth_choices,
    plan_size,
    resolve_depth,
)

FULL = IdentityProfile(
    full_name="Jane Marie Doe",
    location="Austin, TX",
    employer="Initech",
    school="UT Austin",
    age="40",
    phone="555-123-4567",
    email="jane@example.com",
    relatives=("Robert Doe",),
)


def _queries(profile, depth=DEFAULT_DEPTH):
    return [p.query for p in build_plan(profile, depth)]


# --- the central invariant --------------------------------------------------


def test_narrowing_facts_never_enter_the_query():
    """Facts are a ranking input, not a retrieval one.

    Each extra term ANDs against a full-text index, so a query carrying the
    employer, school, age, phone and relatives matches nothing at all and the
    deep scan would return *less* than a plain name search. Location is the one
    deliberate exception and is asserted separately below.
    """
    forbidden = ("Initech", "UT Austin", "40", "555", "jane@example.com", "Robert Doe")
    for query in _queries(FULL, "deep"):
        for term in forbidden:
            assert term not in query, f"{term!r} leaked into {query!r}"


def test_location_is_used_for_retrieval_but_only_in_its_own_pass():
    plan = build_plan(FULL, "standard")
    located = [p for p in plan if "Austin, TX" in p.query]
    assert len(located) == 1
    assert located[0].key == "name_location"


def test_bare_name_pass_runs_even_when_a_location_is_given():
    # A mistyped or wrong city must not be able to hide results that exist.
    keys = [p.key for p in build_plan(FULL, "standard")]
    assert "name_exact" in keys
    assert keys.index("name_location") < keys.index("name_exact")


# --- query construction -----------------------------------------------------


def test_names_are_quoted_as_a_phrase():
    # Unquoted, "Jane Doe" matches a page containing an unrelated Jane and an
    # unrelated Doe.
    assert '"Jane Marie Doe"' in _queries(FULL)[0]


def test_embedded_quotes_are_stripped_not_escaped():
    # The site: / phrase syntax has no escape form; a stray quote would
    # silently truncate the phrase.
    profile = IdentityProfile(full_name='Jane "JD" Doe')
    for query in _queries(profile):
        assert query.count('"') % 2 == 0


def test_site_scoped_passes_drop_the_middle_name():
    """Regression: scoped searches are an exact match against one site's index.

    LinkedIn lists her as "Jane Doe"; scoping to "Jane Marie Doe" turns a hit
    into a miss while the profile sits there in plain sight.
    """
    scoped = [p.query for p in build_plan(FULL, "deep") if p.query.startswith("site:")]
    assert scoped
    for query in scoped:
        assert '"Jane Doe"' in query
        assert "Marie" not in query


def test_site_scoped_passes_cover_the_major_platforms():
    plan = build_plan(FULL, "deep")
    domains = {p.query.split()[0] for p in plan if p.query.startswith("site:")}
    assert "site:linkedin.com" in domains
    assert "site:facebook.com" in domains
    assert "site:instagram.com" in domains


# --- depth tiers ------------------------------------------------------------


def test_depth_tiers_are_strictly_increasing():
    quick, standard, deep = (plan_size(FULL, d) for d in ("quick", "standard", "deep"))
    assert quick < standard < deep


def test_plan_size_matches_the_plan_it_describes():
    # The rate limiter charges by this number; if it drifts from the real plan
    # the limiter silently undercharges the fan-out.
    for depth in ("quick", "standard", "deep"):
        assert plan_size(FULL, depth) == len(build_plan(FULL, depth))


@pytest.mark.parametrize("bad", ["", "DEEP", "enormous", None, 7, object()])
def test_unknown_depth_falls_back_to_the_default(bad):
    assert resolve_depth(bad) == DEFAULT_DEPTH


def test_depth_choices_are_renderable_and_ordered():
    choices = depth_choices()
    assert [c["id"] for c in choices] == ["quick", "standard", "deep"]
    assert all(c["label"] and c["description"] for c in choices)


# --- edge cases -------------------------------------------------------------


def test_no_name_produces_no_plan():
    assert build_plan(IdentityProfile()) == ()
    assert plan_size(IdentityProfile()) == 0


def test_single_token_name_still_produces_a_plan():
    plan = build_plan(IdentityProfile(full_name="Cher"), "standard")
    assert plan
    assert all('"Cher"' in p.query for p in plan)


def test_every_pass_key_is_unique():
    # Outcomes are collected into a dict keyed by pass key; a duplicate would
    # silently drop one pass from the coverage report.
    keys = [p.key for p in build_plan(FULL, "deep")]
    assert len(keys) == len(set(keys))


def test_every_pass_has_a_label_for_the_coverage_panel():
    for pas in build_plan(FULL, "deep"):
        assert pas.label.strip()
        assert pas.group in ("broad", "platforms", "records")
