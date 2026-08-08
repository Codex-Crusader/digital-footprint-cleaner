"""Shared pytest fixtures.

Sets a deterministic SECRET_KEY *before* importing the app so session signing
is stable across the test run, and exposes a configured Flask test client plus
a ready-to-use CSRF token.
"""

import logging
import os

# pytest is a development/test dependency (see requirements-dev.txt), not a
# runtime requirement, so PyCharm's package-requirements check can skip it.
# noinspection PyPackageRequirements
import pytest

# The project root is put on sys.path by `pythonpath = .` in pytest.ini, so no
# manual sys.path juggling is needed here.

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import app as app_module  # noqa: E402  (import after env setup by design)
import scanner  # noqa: E402  (same reason)

# Several tests deliberately exercise failure paths (rejected CSRF tokens, rate
# limiting, unavailable search backend). Those paths log at WARNING by design,
# which is correct in production but just noise in the test report. Raise the
# threshold so expected warnings stay quiet; real errors still surface.
for _name in (
    "app",
    "scanner",
    "utils.petition_writer",
    "utils.email_signals",
    "utils.username_check",
    "utils.tracker",
):
    logging.getLogger(_name).setLevel(logging.ERROR)


@pytest.fixture(autouse=True)
def _ungoverned_search():
    """Run the shared search gate at full speed, and isolate its state.

    The gate paces real upstream requests and widens itself after throttling.
    Both behaviours are correct in production and pure cost in a suite whose
    backend is a fake: the pacing alone added seconds, and the adaptive widening
    leaked between tests, since a test that deliberately raises a 429 would
    otherwise slow down every test that ran after it.
    """
    scanner.reset_governor(interval=0)
    yield
    scanner.reset_governor(interval=0)


@pytest.fixture
def client():
    """A Flask test client with a fresh, isolated rate-limiter state."""
    app_module.app.config.update(TESTING=True)
    app_module.reset_rate_limiter()
    return app_module.app.test_client()


@pytest.fixture
def csrf_token(client):
    """Prime a session (GET /) and return its CSRF token string."""
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf_token"]
