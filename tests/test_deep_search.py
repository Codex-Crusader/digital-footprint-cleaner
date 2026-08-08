"""Tests for the multi-pass scan executor and the shared rate governor.

The theme running through these: a deep scan makes many upstream requests and
some of them will fail. That is the normal case, so the executor's contract is
that partial failure produces partial *results plus honest coverage*, never an
exception and never a silent gap.
"""

# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

import scanner
from utils.identity import IdentityProfile

PROFILE = IdentityProfile(full_name="Jane Doe", location="Austin, TX")


class _ScriptedDDGS:
    """Fake DDGS whose behaviour is chosen per query by a rule table."""

    def __init__(self, rules, calls):
        self._rules = rules
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info):
        return False

    def text(self, query="", max_results=0, **_kwargs):
        self._calls.append(query)
        for needle, outcome in self._rules.items():
            if needle in query:
                if isinstance(outcome, Exception):
                    raise outcome
                return list(outcome)
        return []


def _patch(monkeypatch, rules=None, calls=None):
    calls = calls if calls is not None else []
    monkeypatch.setattr(scanner, "DDGS", lambda: _ScriptedDDGS(rules or {}, calls))
    return calls


def _hit(url, title="Result", body=""):
    return {"title": title, "href": url, "body": body}


# --- happy path -------------------------------------------------------------


def test_runs_every_pass_and_merges_results(monkeypatch):
    _patch(monkeypatch, {"": [_hit("https://example.com/jane")]})
    report = scanner.deep_search(PROFILE, depth="standard")
    assert report.total_passes > 1
    assert report.completed_passes == report.total_passes
    assert report.complete
    assert report.results


def test_results_are_deduplicated_across_passes(monkeypatch):
    # Different passes routinely return the same page; without dedup one
    # profile appears several times and is counted several times in the score.
    _patch(monkeypatch, {"": [_hit("https://example.com/jane")]})
    report = scanner.deep_search(PROFILE, depth="standard")
    assert len(report.results) == 1


def test_duplicates_record_every_pass_that_found_them(monkeypatch):
    _patch(monkeypatch, {"": [_hit("https://example.com/jane")]})
    report = scanner.deep_search(PROFILE, depth="standard")
    assert len(report.results[0]["found_by"]) > 1


@pytest.mark.parametrize(
    "variant",
    [
        "https://example.com/jane/",          # trailing slash
        "https://www.example.com/jane",       # www
        "https://example.com/jane#bio",       # fragment
    ],
)
def test_url_variants_of_one_page_collapse(monkeypatch, variant):
    _patch(monkeypatch, {
        "site:linkedin.com": [_hit(variant)],
        "": [_hit("https://example.com/jane")],
    })
    report = scanner.deep_search(PROFILE, depth="standard")
    urls = {r["url"] for r in report.results}
    assert len(urls) == 1


def test_query_string_is_preserved_when_deduplicating(monkeypatch):
    # Listing IDs live in the query string, so two ?id= values are two pages.
    _patch(monkeypatch, {
        "site:linkedin.com": [_hit("https://example.com/p?id=2")],
        "": [_hit("https://example.com/p?id=1")],
    })
    report = scanner.deep_search(PROFILE, depth="standard")
    assert len(report.results) == 2


def test_unsafe_urls_are_dropped(monkeypatch):
    _patch(monkeypatch, {"": [
        _hit("javascript:alert(1)"),
        _hit("https://example.com/ok"),
    ]})
    report = scanner.deep_search(PROFILE, depth="standard")
    assert [r["url"] for r in report.results] == ["https://example.com/ok"]


def test_results_get_unique_stable_ids(monkeypatch):
    _patch(monkeypatch, {
        "site:linkedin.com": [_hit("https://example.com/a")],
        "site:facebook.com": [_hit("https://example.com/b")],
        "": [_hit("https://example.com/c")],
    })
    report = scanner.deep_search(PROFILE, depth="standard")
    ids = [r["id"] for r in report.results]
    assert len(ids) == len(set(ids))
    assert all(i.startswith("deep_") for i in ids)


# --- partial failure --------------------------------------------------------


def test_one_failing_pass_does_not_lose_the_others(monkeypatch):
    _patch(monkeypatch, {
        "site:linkedin.com": RuntimeError("backend exploded"),
        "": [_hit("https://example.com/jane")],
    })
    report = scanner.deep_search(PROFILE, depth="standard")
    assert report.results  # the good passes still produced results
    assert report.partial
    assert report.failed_passes == 1


def test_total_failure_returns_a_report_rather_than_raising(monkeypatch):
    """An exception here would throw away nothing: but it would also stop the
    caller distinguishing "found nothing" from "could not look"."""
    _patch(monkeypatch, {"": RuntimeError("everything is down")})
    report = scanner.deep_search(PROFILE, depth="standard")
    assert report.results == []
    assert report.completed_passes == 0
    assert report.partial


def test_empty_and_failed_are_never_conflated(monkeypatch):
    # The whole point: "we searched and found nothing" and "the search did not
    # run" must stay distinguishable all the way to the template.
    _patch(monkeypatch, {"site:linkedin.com": RuntimeError("down"), "": []})
    report = scanner.deep_search(PROFILE, depth="standard")
    statuses = {o.key: o.status for o in report.outcomes}
    assert statuses["site_linkedin_com"] == scanner.PASS_FAILED
    assert statuses["name_exact"] == scanner.PASS_EMPTY
    assert any(o.ran for o in report.outcomes)


def test_every_planned_pass_appears_in_the_coverage_report(monkeypatch):
    from utils.search_plan import build_plan

    _patch(monkeypatch, {"": []})
    report = scanner.deep_search(PROFILE, depth="deep")
    planned = {p.key for p in build_plan(PROFILE, "deep")}
    assert {o.key for o in report.outcomes} == planned


def test_gate_refuses_a_slot_once_the_deadline_has_passed():
    # This is what stops a plan hanging: a pass that cannot get a slot in time
    # bails immediately instead of sleeping out the remaining budget.
    import time

    scanner.reset_governor(interval=0)
    assert scanner._acquire_slot(time.monotonic() - 1) is False


def test_budget_exhaustion_marks_passes_skipped_not_clean(monkeypatch):
    """A pass that never ran must not be reported as a pass that found nothing.

    Same contract as `unknown` versus `not_listed` in the broker check: a
    coverage gap presented as a clean result is the failure mode this whole
    report exists to prevent.
    """
    from utils.search_plan import SearchPass

    _patch(monkeypatch, {"": []})
    outcome, items = scanner._run_pass(
        SearchPass(key="p", label="Pass", query="q", group="broad"),
        deadline=0.0,  # already expired
    )
    assert outcome.status == scanner.PASS_SKIPPED
    assert outcome.ran is False
    assert items == []


def test_empty_profile_raises_value_error():
    # A missing name is a caller validation error, not a search failure.
    with pytest.raises(ValueError):
        scanner.deep_search(IdentityProfile())


# --- the shared rate governor ----------------------------------------------


def test_throttling_signal_widens_the_shared_gate(monkeypatch):
    scanner.reset_governor(interval=0.01)
    before = scanner._gate_interval
    _patch(monkeypatch, {"": RuntimeError("429 Too Many Requests")})
    scanner.deep_search(PROFILE, depth="quick")
    assert scanner._gate_interval > before
    scanner.reset_governor(interval=0)


def test_gate_does_not_widen_on_an_ordinary_failure(monkeypatch):
    scanner.reset_governor(interval=0.01)
    before = scanner._gate_interval
    _patch(monkeypatch, {"": ValueError("malformed response")})
    scanner.deep_search(PROFILE, depth="quick")
    assert scanner._gate_interval == before
    scanner.reset_governor(interval=0)


@pytest.mark.parametrize(
    "exc",
    [RuntimeError("429"), RuntimeError("rate limit exceeded"),
     RuntimeError("Too Many Requests")],
)
def test_throttle_detection_recognises_the_usual_shapes(exc):
    assert scanner._looks_throttled(exc)


def test_throttle_detection_ignores_unrelated_errors():
    assert not scanner._looks_throttled(ValueError("bad json"))


def test_gate_widening_is_bounded():
    # Exercised directly rather than through repeated scans: the whole point of
    # the backoff is that it sleeps, so driving it via deep_search would make
    # the suite pay the wait it is meant to be asserting.
    scanner.reset_governor(interval=1.0)
    for _ in range(20):
        scanner._note_throttled()
    assert scanner._gate_interval <= scanner.SEARCH_MAX_INTERVAL
    scanner.reset_governor(interval=0)


def test_gate_narrows_again_as_requests_succeed():
    scanner.reset_governor()
    scanner._note_throttled()
    widened = scanner._gate_interval
    for _ in range(20):
        scanner._note_success()
    assert scanner._gate_interval < widened
    assert scanner._gate_interval >= scanner.SEARCH_MIN_INTERVAL
    scanner.reset_governor(interval=0)


def test_broker_checks_share_the_same_gate(monkeypatch):
    # The governor is only useful if it is genuinely global: a deep scan
    # followed by a broker sweep must not each get their own allowance.
    scanner.reset_governor(interval=0.01)
    scanner.reset_broker_cache()
    before = scanner._gate_interval
    _patch(monkeypatch, {"": RuntimeError("429 rate limit")})
    scanner.check_brokers("Jane Doe", [{"id": "s", "name": "S", "domain": "spokeo.com"}])
    assert scanner._gate_interval > before
    scanner.reset_governor(interval=0)
    scanner.reset_broker_cache()
