"""Tests for the passcode lock and the localhost host-header check.

Auth tests earn their keep by proving the *negative*: that a locked app really
refuses, that a wrong passcode never succeeds, and that the guesses are capped.
A test that only checks the happy path would pass just as well against a lock
that lets everyone in.
"""

import time

# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

from utils import auth

PASSCODE = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _cheap_kdf(monkeypatch):
    """Run the key derivation at a token cost for the duration of the suite.

    The real 600k rounds are the point of the algorithm and deliberately slow;
    paying them once per hashing test took the whole suite from 1s to 8s while
    proving nothing the structure assertions do not. The production figure is
    asserted directly in test_kdf_cost_is_high_enough, which does not use this.
    """
    monkeypatch.setattr(auth, "_PBKDF2_ROUNDS", 1_000)


# --- passcode hashing -------------------------------------------------------


def test_hash_round_trips():
    stored = auth.hash_passcode(PASSCODE)
    assert auth.verify_passcode(PASSCODE, stored)


def test_wrong_passcode_is_rejected():
    stored = auth.hash_passcode(PASSCODE)
    for wrong in ("", "wrong", PASSCODE + " ", PASSCODE.upper(), PASSCODE[:-1]):
        assert not auth.verify_passcode(wrong, stored)


def test_hash_is_salted_so_two_installs_differ():
    # Without a per-install salt, one precomputed table breaks every deployment
    # that chose the same passcode.
    assert auth.hash_passcode(PASSCODE) != auth.hash_passcode(PASSCODE)


def test_plaintext_never_appears_in_the_stored_hash():
    assert PASSCODE not in auth.hash_passcode(PASSCODE)


@pytest.mark.parametrize(
    "malformed",
    ["", "nonsense", "pbkdf2_sha256$notanumber$aa$bb", "md5$1$aa$bb", "a$b$c"],
)
def test_malformed_stored_hash_fails_closed(malformed):
    # A corrupted environment variable must refuse every login, not admit them.
    assert not auth.verify_passcode(PASSCODE, malformed)


def test_hash_format_is_self_describing():
    algorithm, rounds, salt, digest = auth.hash_passcode(PASSCODE).split("$")
    assert algorithm == "pbkdf2_sha256"
    assert int(rounds) == auth._PBKDF2_ROUNDS
    assert len(bytes.fromhex(salt)) >= 16
    assert len(bytes.fromhex(digest)) == 32


def test_kdf_cost_is_high_enough(monkeypatch):
    """The shipped round count, not whatever the suite patches it down to.

    This is the assertion that would catch someone lowering the cost to speed
    something up, which is exactly what the fixture above does temporarily.
    """
    monkeypatch.undo()
    assert auth._PBKDF2_ROUNDS >= 100_000


# --- host header ------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    ["localhost", "localhost:5000", "127.0.0.1", "127.0.0.1:5000", "[::1]", "[::1]:5000"],
)
def test_loopback_hosts_are_allowed(host):
    assert auth.host_is_allowed(host)


@pytest.mark.parametrize(
    "host",
    [
        None,
        "",
        "evil.example",
        "evil.example:5000",
        # The rebinding shape: an attacker domain that resolves to 127.0.0.1.
        "rebind.attacker.test",
        # Trying to smuggle an allowed name into a longer one.
        "localhost.evil.example",
        "notlocalhost",
        "127.0.0.1.evil.example",
    ],
)
def test_foreign_hosts_are_refused(host):
    assert not auth.host_is_allowed(host)


def test_extra_hosts_can_be_configured(monkeypatch):
    monkeypatch.setenv("DFC_ALLOWED_HOSTS", "footprint.lan, other.host")
    assert auth.host_is_allowed("footprint.lan")
    assert auth.host_is_allowed("other.host:8080")
    assert not auth.host_is_allowed("unlisted.host")


# --- idle expiry ------------------------------------------------------------


def test_fresh_session_is_accepted():
    assert auth.session_is_fresh(time.time())


def test_idle_session_expires():
    assert not auth.session_is_fresh(time.time() - auth.IDLE_TIMEOUT_SECONDS - 1)


@pytest.mark.parametrize("tampered", [None, "soon", True, [], {}, float("nan")])
def test_tampered_timestamp_locks_rather_than_unlocks(tampered):
    # A truncated or edited cookie must fail closed.
    assert not auth.session_is_fresh(tampered)


def test_future_timestamp_is_not_trusted():
    # A clock-skewed or forged future value must not grant an unbounded session.
    assert not auth.session_is_fresh(time.time() + 10_000)


# --- login throttling -------------------------------------------------------


def test_attempts_are_capped():
    throttle = auth.LoginThrottle(max_attempts=3, window_seconds=300)
    for _ in range(3):
        assert not throttle.is_locked_out("1.2.3.4")
        throttle.record_failure("1.2.3.4")
    assert throttle.is_locked_out("1.2.3.4")


def test_lockout_is_per_client():
    throttle = auth.LoginThrottle(max_attempts=2, window_seconds=300)
    for _ in range(2):
        throttle.record_failure("1.2.3.4")
    assert throttle.is_locked_out("1.2.3.4")
    assert not throttle.is_locked_out("5.6.7.8")


def test_success_clears_the_counter():
    throttle = auth.LoginThrottle(max_attempts=3, window_seconds=300)
    throttle.record_failure("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    throttle.record_success("1.2.3.4")
    assert not throttle.is_locked_out("1.2.3.4")


def test_lockout_expires_with_the_window():
    throttle = auth.LoginThrottle(max_attempts=1, window_seconds=-1)
    throttle.record_failure("1.2.3.4")
    assert not throttle.is_locked_out("1.2.3.4")


def test_seconds_remaining_is_zero_when_not_locked_out():
    throttle = auth.LoginThrottle(max_attempts=3, window_seconds=300)
    assert throttle.seconds_remaining("1.2.3.4") == 0


# --- what the UI is told ----------------------------------------------------


def test_unlocked_state_is_described_plainly():
    state, explanation = auth.describe_protection(False)
    assert state == "unlocked"
    assert "anyone with access to this computer" in explanation.lower()


def test_locked_state_is_described():
    state, explanation = auth.describe_protection(True)
    assert state == "locked"
    assert "passcode" in explanation.lower()


# --- the lock, wired into the app ------------------------------------------
# LOCK_ENABLED and PASSCODE_HASH are read as module globals on every request,
# so patching them exercises the real before_request path without reimporting
# the app under a different environment.

import app as app_module  # noqa: E402  (imported after the pure-unit tests above)


@pytest.fixture
def locked_client(monkeypatch):
    """A test client for an app instance with the passcode lock switched on."""
    monkeypatch.setattr(app_module, "LOCK_ENABLED", True)
    monkeypatch.setattr(app_module, "PASSCODE_HASH", auth.hash_passcode(PASSCODE))
    app_module.app.config.update(TESTING=True)
    app_module.reset_login_throttle()
    yield app_module.app.test_client()
    app_module.reset_login_throttle()


PROTECTED = ["/", "/dashboard", "/legal", "/about"]


@pytest.mark.parametrize("path", PROTECTED)
def test_locked_app_redirects_every_page_to_login(locked_client, path):
    resp = locked_client.get(path)
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_locked_app_serves_the_login_page(locked_client):
    resp = locked_client.get("/login")
    assert resp.status_code == 200
    assert b"Passcode" in resp.data


def test_correct_passcode_unlocks(locked_client):
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    resp = locked_client.post(
        "/login", data={"passcode": PASSCODE, "csrf_token": token}
    )
    assert resp.status_code == 302
    assert locked_client.get("/").status_code == 200


def test_wrong_passcode_does_not_unlock(locked_client):
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    resp = locked_client.post(
        "/login", data={"passcode": "nope", "csrf_token": token}
    )
    assert resp.status_code == 200
    assert b"Incorrect passcode" in resp.data
    assert locked_client.get("/").status_code == 302


def test_login_is_throttled_after_repeated_failures(locked_client):
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    for _ in range(auth.LOGIN_MAX_ATTEMPTS):
        locked_client.post("/login", data={"passcode": "nope", "csrf_token": token})
    resp = locked_client.post("/login", data={"passcode": "nope", "csrf_token": token})
    assert b"Too many attempts" in resp.data
    # And the correct passcode is refused too while the lockout stands, so the
    # limiter cannot be sidestepped by guessing right on the next try.
    resp = locked_client.post("/login", data={"passcode": PASSCODE, "csrf_token": token})
    assert b"Too many attempts" in resp.data


def test_login_rotates_the_session(locked_client):
    """A session token captured before login must not become an unlocked one."""
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        s["planted"] = "pre-auth value"
        token = s["csrf_token"]
    locked_client.post("/login", data={"passcode": PASSCODE, "csrf_token": token})
    with locked_client.session_transaction() as s:
        assert "planted" not in s
        assert "unlocked_at" in s


def test_lock_route_ends_the_session(locked_client):
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    locked_client.post("/login", data={"passcode": PASSCODE, "csrf_token": token})
    assert locked_client.get("/").status_code == 200

    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    locked_client.post("/lock", data={"csrf_token": token})
    assert locked_client.get("/").status_code == 302


def test_idle_session_is_locked_again(locked_client):
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    locked_client.post("/login", data={"passcode": PASSCODE, "csrf_token": token})
    with locked_client.session_transaction() as s:
        s["unlocked_at"] = time.time() - auth.IDLE_TIMEOUT_SECONDS - 1
    assert locked_client.get("/").status_code == 302


def test_open_redirect_is_not_possible(locked_client):
    # `next` is attacker-controllable; a protocol-relative //host is treated as
    # absolute by browsers, so "starts with /" alone would be an open redirect.
    locked_client.get("/login")
    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    resp = locked_client.post(
        "/login?next=//evil.example/",
        data={"passcode": PASSCODE, "csrf_token": token},
    )
    assert "evil.example" not in resp.headers["Location"]


def test_login_page_is_reachable_without_a_session(locked_client):
    # Otherwise the redirect to /login would itself redirect, forever.
    assert locked_client.get("/login").status_code == 200


# --- host header, wired into the app ---------------------------------------


def test_request_with_a_foreign_host_is_refused(client):
    resp = client.get("/", headers={"Host": "rebind.attacker.test"})
    assert resp.status_code == 403


def test_request_from_localhost_is_served(client):
    assert client.get("/", headers={"Host": "127.0.0.1:5000"}).status_code == 200


def test_static_files_are_also_host_checked(client):
    resp = client.get("/static/css/style.css", headers={"Host": "evil.example"})
    assert resp.status_code == 403


def test_login_returns_you_to_the_page_you_asked_for(locked_client):
    # Regression: the form posted to a bare /login, dropping ?next, so every
    # unlock landed on the home page instead of the page originally requested.
    resp = locked_client.get("/dashboard")
    location = resp.headers["Location"]
    assert "next=%2Fdashboard" in location or "next=/dashboard" in location

    page = locked_client.get("/login?next=/dashboard").data.decode()
    assert "next=%2Fdashboard" in page or "next=/dashboard" in page

    with locked_client.session_transaction() as s:
        token = s["csrf_token"]
    resp = locked_client.post(
        "/login?next=/dashboard", data={"passcode": PASSCODE, "csrf_token": token}
    )
    assert resp.headers["Location"].endswith("/dashboard")
