"""Shared pytest fixtures.

Sets a deterministic SECRET_KEY *before* importing the app so session signing
is stable across the test run, and exposes a configured Flask test client plus
a ready-to-use CSRF token.
"""

import logging
import os
import sys

# pytest is a development/test dependency (see requirements-dev.txt), not a
# runtime requirement, so PyCharm's package-requirements check can skip it.
# noinspection PyPackageRequirements
import pytest

# Ensure the project root is importable when pytest is invoked from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")

import app as app_module  # noqa: E402  (import after env setup by design)

# Several tests deliberately exercise failure paths (rejected CSRF tokens, rate
# limiting, unavailable search backend). Those paths log at WARNING by design,
# which is correct in production but just noise in the test report. Raise the
# threshold so expected warnings stay quiet; real errors still surface.
for _name in ("app", "scanner", "utils.petition_writer"):
    logging.getLogger(_name).setLevel(logging.ERROR)


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
