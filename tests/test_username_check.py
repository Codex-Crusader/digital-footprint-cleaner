import logging
import threading

# httpx is declared in pyproject.toml and requirements.txt; see the note there
# about PyCharm not reading either in this project.
# noinspection PyPackageRequirements
import httpx

# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

from utils import username_check

# The failure paths below log by design; keep the test report free of that noise.
logging.getLogger("utils.username_check").setLevel(logging.ERROR)


class _FakeResponse:
    """Minimal stand-in for httpx.Response: only what _interpret touches."""

    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Offline stand-in for httpx.Client that records what was requested.

    ``outcomes`` maps a URL to a canned response, an exception to raise, or a
    zero-argument callable producing either. ``default`` is used for any URL not
    in the map; a missing default is an error, so no test can silently depend on
    a request it did not plan for.
    """

    def __init__(self, outcomes=None, default=None):
        self._outcomes = outcomes or {}
        self._default = default
        self._lock = threading.Lock()
        self.calls = []
        self.closed = False

    @property
    def urls(self):
        return [url for url, _kwargs in self.calls]

    def get(self, url, **kwargs):
        with self._lock:
            self.calls.append((url, kwargs))
        outcome = self._outcomes.get(url, self._default)
        if outcome is None:
            raise AssertionError(f"unplanned request to {url}")
        if callable(outcome):
            outcome = outcome()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def close(self):
        self.closed = True


def _platform(key="demo", signal=username_check.SIGNAL_STATUS, marker=None):
    """Build a throwaway platform pointing at a non-routable example host."""
    return username_check.Platform(
        key=key,
        name=key.title(),
        url_template=f"https://{key}.example/{{username}}",
        category="social_media",
        signal=signal,
        marker=marker,
    )


def _check(client, platforms, username="octocat", budget=5.0):
    return username_check.check_username(
        username, client=client, platforms=platforms, budget=budget
    )


def test_status_platform_200_is_found():
    platform = _platform()
    client = _FakeClient(default=_FakeResponse(200, "<html>octocat</html>"))
    result = _check(client, [platform])[0]
    assert result["status"] == "found"
    assert result["reason"] == ""
    assert result["http_status"] == 200
    assert result["id"] == "demo"
    assert result["url"] == "https://demo.example/octocat"


def test_confirm_platform_with_marker_is_found():
    platform = _platform(signal=username_check.SIGNAL_CONFIRM, marker="tgme_page_title")
    client = _FakeClient(default=_FakeResponse(200, "<div class='tgme_page_title'>x</div>"))
    result = _check(client, [platform])[0]
    assert result["status"] == "found"


def test_confirm_platform_without_marker_is_unknown_not_missing():
    # The page loaded but nothing proves it is a profile: absence of evidence is
    # not evidence of absence.
    platform = _platform(signal=username_check.SIGNAL_CONFIRM, marker="tgme_page_title")
    client = _FakeClient(default=_FakeResponse(200, "<html>generic landing page</html>"))
    result = _check(client, [platform])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "unconfirmed"


def test_clean_404_is_not_found():
    client = _FakeClient(default=_FakeResponse(404, "Not Found"))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "not_found"
    assert result["reason"] == ""


def test_soft_404_marker_present_is_not_found():
    platform = _platform(signal=username_check.SIGNAL_SOFT_404, marker="could not be found")
    client = _FakeClient(default=_FakeResponse(200, "The specified profile could not be found."))
    result = _check(client, [platform])[0]
    assert result["status"] == "not_found"
    assert result["http_status"] == 200


def test_soft_404_marker_absent_is_found():
    platform = _platform(signal=username_check.SIGNAL_SOFT_404, marker="could not be found")
    client = _FakeClient(default=_FakeResponse(200, "<title>Steam Community :: octocat</title>"))
    result = _check(client, [platform])[0]
    assert result["status"] == "found"


def test_403_is_unknown_blocked():
    client = _FakeClient(default=_FakeResponse(403, "Forbidden"))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "blocked"


def test_429_is_unknown_rate_limited():
    client = _FakeClient(default=_FakeResponse(429, "Too Many Requests"))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "rate limited"


def test_500_is_unknown_server_error():
    client = _FakeClient(default=_FakeResponse(503, ""))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "server error"


def test_redirect_is_unknown_never_found():
    # A 302 usually lands on a login wall or the homepage, not on a profile.
    client = _FakeClient(default=_FakeResponse(302, ""))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "redirected"


def test_timeout_is_unknown_timeout():
    client = _FakeClient(default=httpx.ConnectTimeout("too slow"))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "timeout"


def test_connection_error_is_unknown_network_error():
    client = _FakeClient(default=httpx.ConnectError("dns failure"))
    result = _check(client, [_platform()])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "network error"


def test_unreliable_platform_is_never_requested():
    platform = _platform(signal=username_check.SIGNAL_UNRELIABLE)
    client = _FakeClient()  # no default: any request would raise AssertionError
    result = _check(client, [platform])[0]
    assert result["status"] == "unknown"
    assert result["reason"] == "unreliable"
    assert result["http_status"] is None
    assert client.urls == []


def test_one_raising_platform_does_not_kill_the_batch():
    platforms = [_platform(key="good"), _platform(key="boom"), _platform(key="alsogood")]
    client = _FakeClient(
        outcomes={"https://boom.example/octocat": RuntimeError("unexpected explosion")},
        default=_FakeResponse(200, "ok"),
    )
    results = _check(client, platforms)
    assert [r["status"] for r in results] == ["found", "unknown", "found"]
    assert results[1]["reason"] == "error"


def test_overall_budget_marks_unfinished_platforms_unknown():
    # A gate that is never opened during the call stands in for a hung host, so
    # the deadline is exercised without a real sleep and without flakiness.
    gate = threading.Event()

    def _hang():
        gate.wait(5)
        return _FakeResponse(200, "ok")

    platforms = [_platform(key=f"slow{i}") for i in range(3)]
    client = _FakeClient(default=_hang)
    try:
        results = _check(client, platforms, budget=0.05)
        assert [r["status"] for r in results] == ["unknown"] * 3
        assert {r["reason"] for r in results} == {"timeout"}
    finally:
        # Release the pool threads so nothing lingers into the next test.
        gate.set()


def test_results_keep_platform_order():
    platforms = [_platform(key=f"p{i}") for i in range(5)]
    client = _FakeClient(default=_FakeResponse(200, "ok"))
    results = _check(client, platforms)
    assert [r["id"] for r in results] == ["p0", "p1", "p2", "p3", "p4"]


def test_empty_username_raises():
    with pytest.raises(ValueError):
        username_check.check_username("   ")


def test_non_string_username_raises():
    with pytest.raises(ValueError):
        username_check.check_username(None)


@pytest.mark.parametrize(
    "hostile",
    [
        "../../etc/passwd",
        "..",
        "octo/../../admin",
        "octocat/settings",
        "octocat?redirect=https://evil.example",
        "octocat#fragment",
        "octocat evil",
        "octocat\nHost: evil.example",
        "evil.example/@octocat",
        "octo@evil.example",
        "%2e%2e%2fadmin",
        "-leadinghyphen",
        ".leadingdot",
        # clamp_text strips before truncating, so this one survives the strip
        # and is then cut back to a value *ending* in a newline: the case a
        # trailing-"$" regex would wave through.
        "a" * (username_check.MAX_USERNAME_LENGTH - 1) + "\nb",
    ],
)
def test_hostile_username_is_rejected_before_any_request(hostile):
    # The request target must be unalterable by user input: the value is
    # rejected outright, and the proof is that the client is never called.
    client = _FakeClient(default=_FakeResponse(200, "ok"))
    with pytest.raises(ValueError):
        username_check.check_username(hostile, client=client, platforms=[_platform()])
    assert client.calls == []


def test_valid_username_builds_exactly_the_template_url():
    client = _FakeClient(default=_FakeResponse(200, "ok"))
    username_check.check_username(
        "  Valid.User-name_1  ", client=client, platforms=[_platform()], budget=5.0
    )
    assert client.urls == ["https://demo.example/Valid.User-name_1"]


def test_overlong_username_is_clamped_not_truncated_into_a_new_target():
    client = _FakeClient(default=_FakeResponse(200, "ok"))
    long_name = "a" * (username_check.MAX_USERNAME_LENGTH + 50)
    username_check.check_username(
        long_name, client=client, platforms=[_platform()], budget=5.0
    )
    expected = "a" * username_check.MAX_USERNAME_LENGTH
    assert client.urls == [f"https://demo.example/{expected}"]


def test_per_request_timeout_and_redirect_policy_are_forced():
    # An injected client must not be able to weaken these.
    client = _FakeClient(default=_FakeResponse(200, "ok"))
    _check(client, [_platform()])
    _url, kwargs = client.calls[0]
    assert kwargs["follow_redirects"] is False
    assert kwargs["timeout"] is username_check._REQUEST_TIMEOUT
    assert "DigitalFootprintCleaner" in kwargs["headers"]["User-Agent"]


def test_injected_client_is_not_closed():
    client = _FakeClient(default=_FakeResponse(200, "ok"))
    _check(client, [_platform()])
    assert client.closed is False


def test_client_we_create_is_closed(monkeypatch):
    # Exercises the default-client path without any network: leaking this client
    # would surface as a ResourceWarning, which pytest.ini turns into a failure.
    created = _FakeClient(default=_FakeResponse(200, "ok"))
    monkeypatch.setattr(username_check, "_build_client", lambda: created)
    username_check.check_username("octocat", platforms=[_platform()], budget=5.0)
    assert created.closed is True


def test_client_construction_failure_raises_username_check_error(monkeypatch):
    def _boom():
        raise OSError("no sockets today")

    monkeypatch.setattr(username_check, "_build_client", _boom)
    with pytest.raises(username_check.UsernameCheckError):
        username_check.check_username("octocat", platforms=[_platform()])


def test_empty_platform_list_returns_empty_list():
    client = _FakeClient()
    assert _check(client, []) == []


def test_default_platform_table_is_well_formed():
    keys = [p.key for p in username_check.PLATFORMS]
    assert len(keys) == len(set(keys))
    valid_signals = {
        username_check.SIGNAL_STATUS,
        username_check.SIGNAL_SOFT_404,
        username_check.SIGNAL_CONFIRM,
        username_check.SIGNAL_UNRELIABLE,
    }
    for platform in username_check.PLATFORMS:
        assert platform.signal in valid_signals
        assert platform.url_template.startswith("https://")
        assert platform.url_template.count("{username}") == 1
        # The placeholder must live in the path: a username in the hostname
        # could otherwise steer the request at another site.
        host = platform.url_template.split("//", 1)[1].split("/", 1)[0]
        assert "{username}" not in host
        if platform.signal in (username_check.SIGNAL_SOFT_404, username_check.SIGNAL_CONFIRM):
            assert platform.marker, f"{platform.key} needs a marker for {platform.signal}"


def test_default_platform_table_covers_the_expected_services():
    keys = {p.key for p in username_check.PLATFORMS}
    assert {"github", "reddit", "instagram", "x", "tiktok", "steam", "telegram"} <= keys
