from urllib.parse import urlparse

# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

# httpx is declared in pyproject.toml and requirements.txt; see the note there
# about PyCharm not reading either in this project.
# noinspection PyPackageRequirements
import httpx

from utils import email_signals
from utils.email_signals import (
    FOUND,
    NOT_FOUND,
    UNKNOWN,
    EmailSignalError,
    gather_email_signals,
)

EMAIL = "Jane.Doe@Example.com"
NORMALISED = "jane.doe@example.com"

# Sentinel telling _FakeResponse.json() to fail the way a truncated or HTML
# body would, i.e. with a ValueError rather than an httpx error.
_MALFORMED = object()


class _FakeResponse:
    """Minimal stand-in for httpx.Response: only what the module actually reads."""

    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data
        self.headers = headers or {}

    def json(self):
        if self._json is _MALFORMED:
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self._json


# Which probe a request belongs to, decided from the *parsed* URL: an exact
# hostname plus a path rule.
#
# This deliberately does not test `"api.github.com" in url`. Substring matching
# on a URL is a well-known sanitisation bug -- "https://evil.example/
# api.github.com" contains that string too -- and CodeQL flags it even in tests,
# correctly, because a fake that matches loosely can quietly route a request to
# the wrong probe and make a test pass for the wrong reason.
_ROUTE_MATCHERS = {
    "avatar": lambda p: p.hostname == "www.gravatar.com" and p.path.startswith("/avatar/"),
    "profile": lambda p: p.hostname == "www.gravatar.com" and p.path.endswith(".json"),
    "gravatar": lambda p: p.hostname == "www.gravatar.com",
    "github": lambda p: p.hostname == "api.github.com",
    "any": lambda _p: True,
}


class _FakeClient:
    """Minimal stand-in for httpx.Client, mirroring _FakeDDGS in test_scanner.

    Routes by probe label (see :data:`_ROUTE_MATCHERS`) so a test can script one
    probe and leave the others on the default. Never touches the network;
    constructing a real httpx.Client in tests would also risk a ResourceWarning,
    which pytest.ini turns into an error.
    """

    def __init__(self, routes=None, default=None):
        self._routes = routes or {}
        self._default = default if default is not None else _FakeResponse(status_code=404)
        self.calls = []
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        parsed = urlparse(url)
        for label, outcome in self._routes.items():
            # An unknown label is a typo in a test; fail loudly rather than
            # silently falling through to the default response.
            if _ROUTE_MATCHERS[label](parsed):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
        return self._default

    def close(self):
        self.closed = True


def _profile_payload(**overrides):
    """A realistically-shaped Gravatar profile document."""
    entry = {
        "profileUrl": "https://gravatar.com/janedoe",
        "preferredUsername": "janedoe",
        "displayName": "Jane Doe",
        "thumbnailUrl": "https://gravatar.com/avatar/abc",
        "currentLocation": "Berlin, Germany",
        "job_title": "Staff Engineer",
        "company": "Initech",
        "pronouns": "she/her",
        "aboutMe": "Privacy nerd.",
        "accounts": [
            {
                "domain": "github.com",
                "display": "janedoe",
                "url": "https://github.com/janedoe",
                "shortname": "github",
            }
        ],
        "emails": [{"primary": "true", "value": "jane.doe@example.com"}],
    }
    entry.update(overrides)
    return {"entry": [entry]}


# --- input validation -------------------------------------------------------


@pytest.mark.parametrize("bad", ["", "   ", "not-an-email", "jane@localhost", "a b@c.com", None])
def test_invalid_email_raises_value_error(bad):
    with pytest.raises(ValueError):
        gather_email_signals(bad, client=_FakeClient())


def test_email_is_normalised_and_hashed():
    client = _FakeClient()
    signals = gather_email_signals(EMAIL, client=client)
    assert signals["email"] == NORMALISED
    assert signals["email_redacted"] == "j***@example.com"
    # SHA-256, not MD5: 64 hex characters.
    assert len(signals["email_sha256"]) == 64
    assert signals["email_sha256"] == email_signals.email_digest(NORMALISED)


# --- probe A: Gravatar avatar ----------------------------------------------


def test_avatar_found():
    client = _FakeClient(routes={"avatar": _FakeResponse(status_code=200)})
    avatar = gather_email_signals(EMAIL, client=client)["avatar"]
    assert avatar["state"] == FOUND
    assert avatar["url"].startswith("https://www.gravatar.com/avatar/")


def test_avatar_absent_is_not_found_not_unknown():
    client = _FakeClient(routes={"avatar": _FakeResponse(status_code=404)})
    avatar = gather_email_signals(EMAIL, client=client)["avatar"]
    assert avatar["state"] == NOT_FOUND
    assert avatar["url"] is None


def test_avatar_unexpected_status_is_unknown():
    client = _FakeClient(routes={"avatar": _FakeResponse(status_code=500)})
    assert gather_email_signals(EMAIL, client=client)["avatar"]["state"] == UNKNOWN


# --- probe B: Gravatar profile ---------------------------------------------


def test_profile_parsed_correctly():
    client = _FakeClient(
        routes={"profile": _FakeResponse(status_code=200, json_data=_profile_payload())}
    )
    profile = gather_email_signals(EMAIL, client=client)["profile"]
    assert profile["state"] == FOUND
    assert profile["display_name"] == "Jane Doe"
    assert profile["username"] == "janedoe"
    assert profile["company"] == "Initech"
    assert profile["job_title"] == "Staff Engineer"
    assert profile["location"] == "Berlin, Germany"
    assert profile["pronouns"] == "she/her"
    assert profile["about_me"] == "Privacy nerd."
    assert profile["profile_url"] == "https://gravatar.com/janedoe"
    assert profile["thumbnail_url"] == "https://gravatar.com/avatar/abc"
    assert profile["emails"] == ["jane.doe@example.com"]
    assert profile["accounts"] == [
        {
            "domain": "github.com",
            "display": "janedoe",
            "shortname": "github",
            "url": "https://github.com/janedoe",
        }
    ]


def test_profile_missing_is_not_found():
    client = _FakeClient(routes={"profile": _FakeResponse(status_code=404)})
    assert gather_email_signals(EMAIL, client=client)["profile"]["state"] == NOT_FOUND


def test_profile_malformed_json_is_unknown():
    client = _FakeClient(routes={"profile": _FakeResponse(status_code=200, json_data=_MALFORMED)})
    profile = gather_email_signals(EMAIL, client=client)["profile"]
    assert profile["state"] == UNKNOWN
    # The documented keys still exist, so a template never hits an attribute error.
    assert profile["display_name"] is None
    assert profile["accounts"] == []


@pytest.mark.parametrize(
    "payload",
    [
        {},                       # no "entry" key at all
        {"entry": []},            # present but empty
        {"entry": "not-a-list"},  # wrong type
        {"entry": [None]},        # wrong element type
        ["not", "a", "dict"],     # whole document is the wrong shape
    ],
)
def test_profile_shape_surprises_never_raise(payload):
    client = _FakeClient(routes={"profile": _FakeResponse(status_code=200, json_data=payload)})
    profile = gather_email_signals(EMAIL, client=client)["profile"]
    assert profile["state"] in (NOT_FOUND, UNKNOWN)
    assert profile["accounts"] == []


def test_hostile_account_url_is_rejected():
    payload = _profile_payload(
        accounts=[
            {
                "domain": "evil.example",
                "display": "click me",
                "url": "javascript:alert(document.cookie)",
                "shortname": "evil",
            }
        ],
        profileUrl="javascript:alert(1)",
        thumbnailUrl="data:text/html;base64,PHNjcmlwdD4=",
    )
    client = _FakeClient(routes={"profile": _FakeResponse(status_code=200, json_data=payload)})
    signals = gather_email_signals(EMAIL, client=client)
    profile = signals["profile"]

    # The account is still reported -- the user should learn it exists -- but
    # with no link, so the template cannot render the payload as an href.
    assert profile["accounts"][0]["domain"] == "evil.example"
    assert profile["accounts"][0]["url"] is None
    assert profile["profile_url"] is None
    assert profile["thumbnail_url"] is None
    # Catches a hostile URL surviving in any field, including ones this test
    # does not name explicitly.
    assert "javascript:" not in repr(signals)
    assert "data:text/html" not in repr(signals)


# --- probe C: GitHub --------------------------------------------------------


def test_github_hit():
    payload = {
        "total_count": 1,
        "items": [
            {
                "login": "janedoe",
                "html_url": "https://github.com/janedoe",
                "avatar_url": "https://avatars.githubusercontent.com/u/1",
            }
        ],
    }
    client = _FakeClient(routes={"github": _FakeResponse(200, json_data=payload)})
    github = gather_email_signals(EMAIL, client=client)["github"]
    assert github["state"] == FOUND
    assert github["total_count"] == 1
    assert github["users"][0]["login"] == "janedoe"
    assert github["users"][0]["profile_url"] == "https://github.com/janedoe"


def test_github_zero_results_is_not_found():
    payload = {"total_count": 0, "items": []}
    client = _FakeClient(routes={"github": _FakeResponse(200, json_data=payload)})
    github = gather_email_signals(EMAIL, client=client)["github"]
    assert github["state"] == NOT_FOUND
    assert github["users"] == []


@pytest.mark.parametrize("status", [403, 429])
def test_github_rate_limited_is_unknown(status):
    client = _FakeClient(
        routes={"github": _FakeResponse(status, headers={"X-RateLimit-Remaining": "0"})}
    )
    github = gather_email_signals(EMAIL, client=client)["github"]
    assert github["state"] == UNKNOWN
    assert github["users"] == []
    assert "GITHUB_TOKEN" in github["detail"]


def test_github_token_is_sent_when_present(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    client = _FakeClient()
    gather_email_signals(EMAIL, client=client)
    call = next(c for c in client.calls if urlparse(c["url"]).hostname == "api.github.com")
    assert call["headers"]["Authorization"] == "Bearer ghp_secret"


def test_github_token_absent_sends_no_auth_header(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    client = _FakeClient()
    gather_email_signals(EMAIL, client=client)
    call = next(c for c in client.calls if urlparse(c["url"]).hostname == "api.github.com")
    assert "Authorization" not in call["headers"]


def test_github_email_travels_as_a_parameter_not_in_the_url():
    client = _FakeClient()
    gather_email_signals(EMAIL, client=client)
    call = next(c for c in client.calls if urlparse(c["url"]).hostname == "api.github.com")
    assert NORMALISED not in call["url"]
    assert call["params"]["q"] == f"{NORMALISED} in:email"


# --- transport failures -----------------------------------------------------


def test_network_timeout_is_unknown_everywhere():
    timeout = httpx.ConnectTimeout("connection timed out")
    client = _FakeClient(
        routes={"gravatar": timeout, "github": timeout},
    )
    signals = gather_email_signals(EMAIL, client=client)
    assert signals["avatar"]["state"] == UNKNOWN
    assert signals["profile"]["state"] == UNKNOWN
    assert signals["github"]["state"] == UNKNOWN
    assert signals["summary"]["unknown_count"] == 3
    assert signals["summary"]["partial"] is True
    assert signals["summary"]["any_found"] is False


def test_unsupported_redirect_scheme_is_unknown():
    # httpx refuses to dispatch a redirect to a non-http(s) scheme; that must
    # degrade to "unknown", not escape to the caller.
    client = _FakeClient(routes={"gravatar": httpx.UnsupportedProtocol("bad scheme")})
    signals = gather_email_signals(EMAIL, client=client)
    assert signals["avatar"]["state"] == UNKNOWN
    assert signals["profile"]["state"] == UNKNOWN


def test_request_helper_raises_email_signal_error():
    assert issubclass(EmailSignalError, RuntimeError)
    client = _FakeClient(routes={"any": httpx.ReadTimeout("slow")})
    with pytest.raises(EmailSignalError):
        email_signals._request(client, "https://example.com/probe", "test")


# --- cross-cutting guarantees ----------------------------------------------


def test_timeout_and_user_agent_on_every_request():
    client = _FakeClient()
    gather_email_signals(EMAIL, client=client)
    assert len(client.calls) == 3
    for call in client.calls:
        assert call["timeout"] is email_signals._TIMEOUT
        assert email_signals.USER_AGENT in call["headers"]["User-Agent"]


def test_injected_client_is_not_closed():
    client = _FakeClient()
    gather_email_signals(EMAIL, client=client)
    assert client.closed is False


def test_summary_counts_mixed_states():
    client = _FakeClient(
        routes={
            "avatar": _FakeResponse(status_code=200),
            "profile": _FakeResponse(status_code=404),
            "github": _FakeResponse(status_code=403),
        }
    )
    summary = gather_email_signals(EMAIL, client=client)["summary"]
    assert summary == {
        "found_count": 1,
        "not_found_count": 1,
        "unknown_count": 1,
        "any_found": True,
        "partial": True,
    }


def test_default_client_is_configured_defensively():
    # Constructing a client opens no connection, and the context manager closes
    # it -- a leak would surface as a ResourceWarning, which pytest.ini escalates
    # to an error. This is the only test that touches the production default.
    with email_signals._build_client() as client:
        assert client.timeout.connect == email_signals.CONNECT_TIMEOUT_SECONDS
        assert client.timeout.read == email_signals.READ_TIMEOUT_SECONDS
        assert client.headers["User-Agent"] == email_signals.USER_AGENT
        assert client.max_redirects == 3


# --- Regression: a malformed 200 must never read as "you are not exposed" ---
# Absence is signalled by an explicit 404. A 200 whose body is not the expected
# shape (proxy interference, captive portal, API change) means the check did not
# actually happen, so it must resolve to 'unknown', never 'not_found'.


def test_gravatar_profile_200_with_unexpected_shape_is_unknown():
    client = _FakeClient(routes={"profile": _FakeResponse(200, {"unexpected": "shape"})})
    assert gather_email_signals(EMAIL, client=client)["profile"]["state"] == UNKNOWN


def test_gravatar_profile_200_with_non_list_entry_is_unknown():
    client = _FakeClient(routes={"profile": _FakeResponse(200, {"entry": {"a": 1}})})
    assert gather_email_signals(EMAIL, client=client)["profile"]["state"] == UNKNOWN


def test_gravatar_profile_404_is_still_not_found():
    # The genuine absence signal must keep working after the tightening above.
    client = _FakeClient(routes={"profile": _FakeResponse(404, None)})
    assert gather_email_signals(EMAIL, client=client)["profile"]["state"] == NOT_FOUND


def test_github_200_missing_total_count_is_unknown():
    client = _FakeClient(routes={"github": _FakeResponse(200, {"items": []})})
    assert gather_email_signals(EMAIL, client=client)["github"]["state"] == UNKNOWN


def test_github_200_with_non_list_items_is_unknown():
    client = _FakeClient(
        routes={"github": _FakeResponse(200, {"total_count": 0, "items": {}})}
    )
    assert gather_email_signals(EMAIL, client=client)["github"]["state"] == UNKNOWN


def test_github_200_with_well_formed_empty_result_is_not_found():
    # A complete, valid "zero results" body IS evidence of absence.
    client = _FakeClient(
        routes={"github": _FakeResponse(200, {"total_count": 0, "items": []})}
    )
    assert gather_email_signals(EMAIL, client=client)["github"]["state"] == NOT_FOUND


def test_full_email_is_never_logged_above_debug(caplog):
    caplog.set_level("INFO", logger="utils.email_signals")
    client = _FakeClient(routes={"gravatar": httpx.ConnectTimeout("nope")})
    gather_email_signals(EMAIL, client=client)
    assert NORMALISED not in caplog.text
    assert EMAIL not in caplog.text
    assert "j***@example.com" in caplog.text
