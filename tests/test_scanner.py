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
