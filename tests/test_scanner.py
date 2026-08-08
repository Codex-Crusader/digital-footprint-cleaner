# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

import scanner


class _FakeDDGS:
    """Minimal stand-in for ddgs.DDGS used as a context manager."""

    def __init__(self, results=None, raise_exc=None):
        self._results = results or []
        self._raise = raise_exc

    def __enter__(self):
        return self

    def __exit__(self, *_exc_info):
        return False

    def text(self, **_kwargs):
        if self._raise:
            raise self._raise
        return self._results


def _patch_ddgs(monkeypatch, results=None, raise_exc=None):
    monkeypatch.setattr(
        scanner, "DDGS", lambda: _FakeDDGS(results=results, raise_exc=raise_exc)
    )


def test_find_footprint_returns_sanitised_results(monkeypatch):
    _patch_ddgs(
        monkeypatch,
        results=[
            {"title": "Profile", "href": "https://example.com/jane", "body": "bio"},
            {"title": "Bad", "href": "javascript:alert(1)", "body": "x"},  # dropped
        ],
    )
    results = scanner.find_footprint("Jane Doe")
    assert len(results) == 1
    assert results[0]["url"] == "https://example.com/jane"
    assert results[0]["id"] == "duck_0"


def test_find_footprint_fills_missing_title(monkeypatch):
    _patch_ddgs(monkeypatch, results=[{"href": "https://example.com", "body": ""}])
    results = scanner.find_footprint("x")
    assert results[0]["title"] == "Untitled result"


def test_find_footprint_empty_query_raises():
    with pytest.raises(ValueError):
        scanner.find_footprint("   ")


def test_find_footprint_backend_failure_raises_search_error(monkeypatch):
    _patch_ddgs(monkeypatch, raise_exc=RuntimeError("429 rate limited"))
    with pytest.raises(scanner.SearchError):
        scanner.find_footprint("Jane Doe")


# --- Site-scoped broker checks ----------------------------------------------


@pytest.fixture(autouse=True)
def _clear_broker_cache():
    """The broker cache is module-level; isolate every test from the last."""
    scanner.reset_broker_cache()
    yield
    scanner.reset_broker_cache()


class _RecordingDDGS(_FakeDDGS):
    """Fake DDGS that records the queries it was asked for."""

    def __init__(self, results=None, raise_exc=None, calls=None):
        super().__init__(results=results, raise_exc=raise_exc)
        self._calls = calls if calls is not None else []

    def text(self, **kwargs):
        self._calls.append(kwargs.get("query", ""))
        return super().text(**kwargs)


def _patch_recording(monkeypatch, results=None, raise_exc=None):
    calls = []
    monkeypatch.setattr(
        scanner,
        "DDGS",
        lambda: _RecordingDDGS(results=results, raise_exc=raise_exc, calls=calls),
    )
    return calls


_BROKERS = [
    {"id": "spokeo", "name": "Spokeo", "domain": "spokeo.com",
     "opt_out_url": "https://www.spokeo.com/optout"},
    {"id": "radaris", "name": "Radaris", "domain": "radaris.com",
     "opt_out_url": "https://radaris.com/optout"},
]


def test_check_broker_reports_listed_for_on_domain_hit(monkeypatch):
    calls = _patch_recording(
        monkeypatch, results=[{"href": "https://www.spokeo.com/Jane-Doe", "title": "J"}]
    )
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "listed"
    # The search must actually be scoped to the broker's domain.
    assert calls == ['site:spokeo.com "Jane Doe"']


def test_check_broker_matches_subdomains(monkeypatch):
    _patch_recording(
        monkeypatch, results=[{"href": "https://profiles.spokeo.com/jane", "title": "J"}]
    )
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "listed"


def test_check_broker_ignores_off_domain_results(monkeypatch):
    # Search engines return pages that merely *mention* a broker. Counting
    # those would tell users they are listed when they are not.
    _patch_recording(
        monkeypatch,
        results=[
            {"href": "https://reddit.com/r/privacy/how-to-leave-spokeo", "title": "x"},
            {"href": "https://not-spokeo.com/jane", "title": "y"},
        ],
    )
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "not_listed"


def test_check_broker_ignores_unsafe_urls(monkeypatch):
    _patch_recording(monkeypatch, results=[{"href": "javascript:alert(1)", "title": "x"}])
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "not_listed"


def test_check_broker_returns_unknown_on_backend_failure(monkeypatch):
    _patch_recording(monkeypatch, raise_exc=RuntimeError("429 rate limited"))
    # Crucially not "not_listed" -- a failed check is not evidence of absence.
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "unknown"


def test_check_broker_caches_answers_but_not_unknowns(monkeypatch):
    calls = _patch_recording(
        monkeypatch, results=[{"href": "https://www.spokeo.com/Jane", "title": "J"}]
    )
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "listed"
    assert scanner.check_broker("Jane Doe", "spokeo.com") == "listed"
    assert len(calls) == 1  # second call served from cache

    fail_calls = _patch_recording(monkeypatch, raise_exc=RuntimeError("boom"))
    assert scanner.check_broker("Other Person", "radaris.com") == "unknown"
    assert scanner.check_broker("Other Person", "radaris.com") == "unknown"
    assert len(fail_calls) == 2  # 'unknown' must never be cached


def test_check_broker_blank_input_is_unknown(monkeypatch):
    calls = _patch_recording(monkeypatch, results=[])
    assert scanner.check_broker("", "spokeo.com") == "unknown"
    assert scanner.check_broker("Jane", "") == "unknown"
    assert calls == []  # never reaches the backend


def test_check_brokers_marks_uncovered_brokers_as_skipped(monkeypatch):
    _patch_recording(monkeypatch, results=[])
    report = scanner.check_brokers("Jane Doe", _BROKERS, max_checks=1)
    assert [r["status"] for r in report] == ["not_listed", "skipped"]
    # Skipped entries are still returned so the UI can be honest about coverage.
    assert report[1]["name"] == "Radaris"


def test_check_brokers_preserves_registry_fields(monkeypatch):
    _patch_recording(monkeypatch, results=[])
    report = scanner.check_brokers("Jane Doe", _BROKERS)
    assert report[0]["opt_out_url"] == "https://www.spokeo.com/optout"
    assert report[0]["id"] == "spokeo"


def test_check_brokers_empty_query_raises():
    with pytest.raises(ValueError):
        scanner.check_brokers("   ", _BROKERS)


def test_check_brokers_handles_empty_and_malformed_registry(monkeypatch):
    _patch_recording(monkeypatch, results=[])
    assert scanner.check_brokers("Jane", []) == []
    # Entries without a domain are dropped rather than crashing the batch.
    assert scanner.check_brokers("Jane", [{"id": "x"}, "not-a-dict"]) == []
