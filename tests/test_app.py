# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

import app as app_module
import scanner
from utils import search_plan
from utils.identity import IdentityProfile


def _patch_scan(monkeypatch, results=(), raises=None, outcomes=None):
    """Make the deep scan return canned results without touching the network.

    Replaces `scanner.deep_search` rather than a name imported into `app`, so
    the fake sits at the real seam: `app` calls it through the module.
    """
    def fake(_profile, depth=None, **_kwargs):
        if raises is not None:
            raise raises
        report = scanner.DeepSearchReport(results=[dict(r) for r in results])
        report.outcomes = list(outcomes) if outcomes is not None else [
            scanner.PassOutcome(
                key="name_exact",
                label="Exact name",
                group="broad",
                status=scanner.PASS_OK if results else scanner.PASS_EMPTY,
                count=len(results),
            )
        ]
        return report

    monkeypatch.setattr(scanner, "deep_search", fake)


# --- Security headers -------------------------------------------------------
def test_headers_present_on_every_response(client):
    resp = client.get("/")
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


# --- CSRF -------------------------------------------------------------------
def test_post_without_token_is_rejected(client):
    resp = client.post("/", data={"user_info": "Jane"})
    assert resp.status_code == 400


def test_post_with_wrong_token_is_rejected(client):
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": "wrong"})
    assert resp.status_code == 400


def test_post_with_valid_token_passes(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch)
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert resp.status_code == 200


# --- Search flow ------------------------------------------------------------
def test_empty_input_shows_prompt(client, csrf_token):
    resp = client.post("/", data={"user_info": "   ", "csrf_token": csrf_token})
    assert resp.status_code == 200
    assert b"Please provide a name to search for" in resp.data


def test_no_results_message(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch)
    resp = client.post("/", data={"user_info": "Nobody", "csrf_token": csrf_token})
    assert b"No web results found" in resp.data


def test_total_backend_failure_never_reads_as_a_clean_result(client, csrf_token, monkeypatch):
    """Every pass failing must not render like "we looked and found nothing".

    This is the most consequential thing this UI can get wrong. A throttled
    sweep and a genuinely clean footprint both produce zero results; if the page
    cannot tell them apart, it tells someone their data is not exposed at a
    moment when nobody actually managed to look.
    """
    _patch_scan(
        monkeypatch,
        outcomes=[
            scanner.PassOutcome(key="name_exact", label="Exact name", group="broad",
                                status=scanner.PASS_FAILED, detail="backend down"),
            scanner.PassOutcome(key="site_x_com", label="X / Twitter", group="platforms",
                                status=scanner.PASS_FAILED, detail="backend down"),
        ],
    )
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert resp.status_code == 200
    assert b"No web results found" not in resp.data
    assert b"could not be completed" in resp.data


def test_partial_coverage_is_reported_alongside_results(client, csrf_token, monkeypatch):
    _patch_scan(
        monkeypatch,
        results=[{"id": "deep_0", "title": "Profile",
                  "url": "https://example.com/jane", "snippet": ""}],
        outcomes=[
            scanner.PassOutcome(key="name_exact", label="Exact name", group="broad",
                                status=scanner.PASS_OK, count=1),
            scanner.PassOutcome(key="site_x_com", label="X / Twitter", group="platforms",
                                status=scanner.PASS_FAILED, detail="throttled"),
        ],
    )
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert b"1 of 2" in resp.data


def test_unexpected_scan_error_shows_friendly_message(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch, raises=RuntimeError("boom"))
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert b"error processing your request" in resp.data


def test_broker_result_shows_exposure_and_opt_out(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch, results=[
            {
                "id": "duck_0",
                "title": "Jane Doe - Spokeo",
                "url": "https://www.spokeo.com/Jane-Doe",
                "snippet": "address, phone",
            }
        ])
    resp = client.post("/", data={"user_info": "Jane Doe", "csrf_token": csrf_token})
    assert b"exposure" in resp.data
    assert b"data brokers" in resp.data
    assert b"https://www.spokeo.com/optout" in resp.data  # verified opt-out link


def test_broker_checklist_shows_scoped_check_link_after_scan(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch)
    resp = client.post("/", data={"user_info": "Jane Doe", "csrf_token": csrf_token})
    # A scoped DuckDuckGo "Check" link is generated per broker so the user can
    # confirm whether a broker actually lists them. Assert the full check URL
    # (with scheme) rather than a bare host substring.
    assert b"https://duckduckgo.com/?q=site%3Aspokeo.com" in resp.data


def test_landing_page_has_no_check_links(client):
    # Before any search there is no name to scope a check to.
    resp = client.get("/")
    assert b"https://duckduckgo.com/?q=site" not in resp.data


def test_results_render_with_safe_link(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch, results=[
            {
                "id": "duck_0",
                "title": "Profile",
                "url": "https://example.com/jane",
                "snippet": "bio",
            }
        ])
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert b'rel="noopener noreferrer"' in resp.data
    assert b"https://example.com/jane" in resp.data


# --- Send flow --------------------------------------------------------------
def test_send_renders_generated_petitions(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch, results=[
            {
                "id": "duck_0",
                "title": "Profile",
                "url": "https://example.com/jane",
                "snippet": "",
            }
        ])
    client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    resp = client.post(
        "/send",
        data={
            "selected_sites": "duck_0",
            "user_name": "Jane Doe",
            "csrf_token": csrf_token,
        },
    )
    assert resp.status_code == 200
    assert b"Generated petitions" in resp.data
    assert b"https://example.com/jane" in resp.data


def test_send_with_no_selection_redirects(client, csrf_token):
    resp = client.post("/send", data={"csrf_token": csrf_token})
    assert resp.status_code == 302


# --- Rate limiting ----------------------------------------------------------
def test_search_is_rate_limited(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch)
    # A scan is charged the size of the plan it is about to run, so the budget
    # here is expressed in plans rather than in requests.
    cost = search_plan.plan_size(IdentityProfile(full_name="Jane"), "standard")
    monkeypatch.setattr(app_module, "SEARCH_RATE_LIMIT", cost * 2)
    for _ in range(2):
        ok = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
        assert b"Too many searches" not in ok.data
    blocked = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert b"Too many searches" in blocked.data


def test_deep_scan_is_charged_more_than_a_quick_one(client, csrf_token, monkeypatch):
    """The limiter must price a scan by the requests it actually makes.

    A deep plan issues several times the upstream searches of a quick one.
    Charging both a flat token would let a client drain the search provider's
    quota with a handful of clicks, after which every user gets throttled.
    """
    _patch_scan(monkeypatch)
    profile = IdentityProfile(full_name="Jane Doe", location="Austin")
    quick = search_plan.plan_size(profile, "quick")
    deep = search_plan.plan_size(profile, "deep")
    assert deep > quick

    # A budget that comfortably fits one quick scan but not one deep scan.
    monkeypatch.setattr(app_module, "SEARCH_RATE_LIMIT", deep - 1)
    form = {"user_info": "Jane Doe", "location": "Austin", "csrf_token": csrf_token}

    app_module.reset_rate_limiter()
    allowed = client.post("/", data={**form, "depth": "quick"})
    assert b"Too many searches" not in allowed.data

    app_module.reset_rate_limiter()
    blocked = client.post("/", data={**form, "depth": "deep"})
    assert b"Too many searches" in blocked.data


def test_fanout_endpoints_cost_more_than_one_token(client, csrf_token, monkeypatch):
    # A broker sweep issues many upstream searches; charging it one token would
    # let a client drain the provider's quota in a couple of clicks.
    monkeypatch.setattr(app_module, "SEARCH_RATE_LIMIT", 5)
    monkeypatch.setattr(app_module, "BROKER_SWEEP_COST", 8)
    monkeypatch.setattr(app_module.scanner, "check_brokers", lambda *a, **k: [])

    resp = client.post(
        "/check-brokers",
        data={"user_info": "Jane Doe", "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"Too many searches" in resp.data


# --- Broker deep check ------------------------------------------------------
def _fake_checks(*_args, **_kwargs):
    return [
        {"id": "spokeo", "name": "Spokeo", "domain": "spokeo.com",
         "opt_out_url": "https://www.spokeo.com/optout", "status": "listed"},
        {"id": "radaris", "name": "Radaris", "domain": "radaris.com",
         "opt_out_url": "https://radaris.com/optout", "status": "not_listed"},
        {"id": "beenverified", "name": "BeenVerified", "domain": "beenverified.com",
         "opt_out_url": "https://www.beenverified.com/app/optout/search",
         "status": "unknown"},
    ]


def test_broker_sweep_renders_all_three_states(client, csrf_token, monkeypatch):
    monkeypatch.setattr(app_module.scanner, "check_brokers", _fake_checks)
    resp = client.post(
        "/check-brokers", data={"user_info": "Jane Doe", "csrf_token": csrf_token}
    )
    assert resp.status_code == 200
    # Each state gets its own CSS class so 'unknown' can never look like a pass.
    assert b"check-listed" in resp.data
    assert b"check-not_listed" in resp.data
    assert b"check-unknown" in resp.data
    assert b"https://www.spokeo.com/optout" in resp.data


def test_broker_sweep_without_a_name_redirects(client, csrf_token):
    resp = client.post("/check-brokers", data={"csrf_token": csrf_token})
    assert resp.status_code == 302


def test_blank_name_does_not_silently_reuse_the_previous_query(
    client, csrf_token, monkeypatch
):
    # Regression: an explicitly *blank* field must not fall back to whatever was
    # scanned earlier. Doing so would send a previous name or email to every
    # broker without the user asking for it in this request.
    _patch_scan(monkeypatch)
    calls = []
    monkeypatch.setattr(
        app_module.scanner,
        "check_brokers",
        lambda query, *_a, **_k: calls.append(query) or [],
    )
    client.post("/", data={"user_info": "Jane Doe", "csrf_token": csrf_token})

    resp = client.post(
        "/check-brokers", data={"user_info": "   ", "csrf_token": csrf_token}
    )
    assert resp.status_code == 302  # rejected, not silently re-run
    assert calls == []  # nothing was sent to any broker


def test_username_cost_matches_the_platforms_actually_requested(monkeypatch):
    # Regression: this was hardcoded to 6 while 12 platforms were really being
    # requested, so the limiter undercharged the fan-out by half.
    requested = [
        p for p in app_module.username_check.PLATFORMS
        if p.signal != app_module.username_check.SIGNAL_UNRELIABLE
    ]
    assert app_module.USERNAME_CHECK_COST == len(requested)
    assert app_module.USERNAME_CHECK_COST > 0


def test_broker_sweep_falls_back_to_last_query(client, csrf_token, monkeypatch):
    _patch_scan(monkeypatch)
    monkeypatch.setattr(app_module.scanner, "check_brokers", _fake_checks)
    client.post("/", data={"user_info": "Jane Doe", "csrf_token": csrf_token})
    # No user_info supplied: the name from the previous scan is reused.
    resp = client.post("/check-brokers", data={"csrf_token": csrf_token})
    assert resp.status_code == 200
    assert b"check-listed" in resp.data


# --- Email signals ----------------------------------------------------------
def _fake_signals(*_args, **_kwargs):
    return {
        "email": "jane@example.com",
        "email_redacted": "j***@example.com",
        "email_sha256": "abc123",
        "avatar": {"state": "found", "url": "https://www.gravatar.com/avatar/abc123",
                   "detail": "An avatar is published for this address."},
        "profile": {
            "state": "found", "detail": "Public profile found.",
            "profile_url": "https://gravatar.com/janedoe", "username": "janedoe",
            "display_name": "Jane Doe", "thumbnail_url": None,
            "location": "Austin, TX", "job_title": "Engineer", "company": "Acme",
            "pronouns": None, "about_me": None,
            "accounts": [
                {"domain": "github.com", "display": "janedoe",
                 "shortname": "github", "url": "https://github.com/janedoe"},
                {"domain": "evil.example", "display": "hostile",
                 "shortname": "x", "url": None},
            ],
            "emails": [],
        },
        "github": {"state": "unknown", "detail": "Rate limited.",
                   "total_count": 0, "users": []},
        "summary": {"found_count": 2, "not_found_count": 0, "unknown_count": 1,
                    "any_found": True, "partial": True},
    }


def test_email_signals_render_profile_and_accounts(client, csrf_token, monkeypatch):
    monkeypatch.setattr(app_module.email_signals, "gather_email_signals", _fake_signals)
    resp = client.post(
        "/signals", data={"email": "jane@example.com", "csrf_token": csrf_token}
    )
    assert resp.status_code == 200
    assert b"j***@example.com" in resp.data  # redacted, never the full address
    assert b"Austin, TX" in resp.data
    assert b"https://github.com/janedoe" in resp.data
    # An account whose URL failed validation is still disclosed, without a link.
    assert b"link withheld" in resp.data
    # A partial run warns rather than implying a clean bill of health.
    assert b"could not complete" in resp.data


def test_email_signals_rejects_invalid_address(client, csrf_token, monkeypatch):
    def boom(*_args, **_kwargs):
        raise ValueError("bad email")

    monkeypatch.setattr(app_module.email_signals, "gather_email_signals", boom)
    resp = client.post("/signals", data={"email": "nope", "csrf_token": csrf_token})
    assert resp.status_code == 302


def test_email_signals_requires_input(client, csrf_token):
    resp = client.post("/signals", data={"email": "  ", "csrf_token": csrf_token})
    assert resp.status_code == 302


# --- Username presence ------------------------------------------------------
def _fake_username_results(*_args, **_kwargs):
    return [
        {"id": "github", "platform": "GitHub", "category": "professional",
         "url": "https://github.com/janedoe", "status": "found", "reason": "",
         "http_status": 200, "note": ""},
        {"id": "reddit", "platform": "Reddit", "category": "forum",
         "url": "https://www.reddit.com/user/janedoe", "status": "not_found",
         "reason": "", "http_status": 404, "note": ""},
        {"id": "instagram", "platform": "Instagram", "category": "social_media",
         "url": "https://www.instagram.com/janedoe/", "status": "unknown",
         "reason": "unreliable", "http_status": None,
         "note": "Returns 200 for every handle."},
    ]


def test_username_check_renders_all_three_states(client, csrf_token, monkeypatch):
    monkeypatch.setattr(
        app_module.username_check, "check_username", _fake_username_results
    )
    resp = client.post(
        "/username", data={"username": "janedoe", "csrf_token": csrf_token}
    )
    assert resp.status_code == 200
    assert b"check-found" in resp.data
    assert b"check-not_found" in resp.data
    assert b"check-unknown" in resp.data
    assert b"https://github.com/janedoe" in resp.data
    assert b"unreliable" in resp.data  # the reason is shown, not hidden


def test_username_check_rejects_hostile_input(client, csrf_token, monkeypatch):
    def boom(*_args, **_kwargs):
        raise ValueError("bad username")

    monkeypatch.setattr(app_module.username_check, "check_username", boom)
    resp = client.post(
        "/username", data={"username": "../../etc/passwd", "csrf_token": csrf_token}
    )
    assert resp.status_code == 302


# --- Petitions from the broker checklist ------------------------------------
def test_send_generates_petition_for_a_broker_id(client, csrf_token):
    resp = client.post(
        "/send",
        data={
            "selected_sites": "broker_spokeo",
            "user_name": "Jane Doe",
            "legal_basis": "gdpr",
            "data_types": ["address", "phone"],
            "csrf_token": csrf_token,
        },
    )
    assert resp.status_code == 200
    assert b"Generated petitions" in resp.data
    assert b"Spokeo" in resp.data
    assert b"Article 17" in resp.data  # the chosen legal basis is cited
    assert b"telephone number" in resp.data  # the chosen data types are named


# --- Removal tracker dashboard ----------------------------------------------
@pytest.fixture
def tracker_db(monkeypatch, tmp_path):
    """Point the tracker at a throwaway database for dashboard tests."""
    monkeypatch.setenv("DFC_DB_PATH", str(tmp_path / "dashboard.sqlite3"))


def test_dashboard_renders_when_empty(client, tracker_db):
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"Nothing tracked yet" in resp.data


def test_dashboard_add_update_and_purge(client, csrf_token, tracker_db):
    added = client.post(
        "/dashboard/add",
        data={"site_name": "Spokeo", "broker_id": "spokeo",
              "notes": "sent via web form", "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"Spokeo" in added.data
    assert b"sent via web form" in added.data
    # Selecting a known broker pulls in its verified opt-out link.
    assert b"https://www.spokeo.com/optout" in added.data

    listed = client.get("/dashboard")
    request_id = app_module.tracker.list_requests()[0]["id"]
    assert b"todo" in listed.data

    updated = client.post(
        "/dashboard/update",
        data={"request_id": str(request_id), "status": "removed",
              "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"Status updated" in updated.data
    assert app_module.tracker.list_requests()[0]["status"] == "removed"

    purged = client.post(
        "/dashboard/purge", data={"csrf_token": csrf_token}, follow_redirects=True
    )
    assert b"Deleted 1 tracked request" in purged.data
    assert app_module.tracker.list_requests() == []


def test_dashboard_add_requires_a_site_name(client, csrf_token, tracker_db):
    resp = client.post(
        "/dashboard/add", data={"site_name": "  ", "csrf_token": csrf_token}
    )
    assert resp.status_code == 302
    assert app_module.tracker.list_requests() == []


def test_dashboard_rejects_unknown_status(client, csrf_token, tracker_db):
    request_id = app_module.tracker.add_request("Spokeo")
    resp = client.post(
        "/dashboard/update",
        data={"request_id": str(request_id), "status": "teleported",
              "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"Unknown status" in resp.data


def test_dashboard_delete_entry(client, csrf_token, tracker_db):
    request_id = app_module.tracker.add_request("Radaris")
    resp = client.post(
        "/dashboard/update",
        data={"request_id": str(request_id), "action": "delete",
              "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"Entry deleted" in resp.data
    assert app_module.tracker.list_requests() == []


def test_dashboard_tolerates_a_non_numeric_id(client, csrf_token, tracker_db):
    resp = client.post(
        "/dashboard/update",
        data={"request_id": "not-a-number", "csrf_token": csrf_token},
    )
    assert resp.status_code == 302


# --- CSRF applies to every new POST route -----------------------------------
@pytest.mark.parametrize(
    "route",
    ["/check-brokers", "/signals", "/username",
     "/dashboard/add", "/dashboard/update", "/dashboard/purge"],
)
def test_new_post_routes_require_csrf(client, route):
    assert client.post(route, data={}).status_code == 400


# --- Result storage across the scan -> petition round trip -------------------
def test_large_scan_survives_the_send_round_trip(client, csrf_token, monkeypatch):
    """A deep scan's results must still be resolvable when /send is posted.

    Regression for a silent failure: the id-to-URL map used to live in the Flask
    session, which is a signed cookie. Ten results fitted; a deep scan's hundred
    do not, so the browser dropped an oversized cookie and petition generation
    reported "nothing could be generated" with nothing explaining why.
    """
    results = [
        {"id": f"deep_{i}", "title": f"Result {i}",
         "url": f"https://example-{i}.com/jane-doe-profile-page", "snippet": "x" * 80}
        for i in range(120)
    ]
    _patch_scan(monkeypatch, results=results)

    scan = client.post("/", data={"user_info": "Jane Doe", "csrf_token": csrf_token})
    assert scan.status_code == 200

    # The cookie must stay small: it carries a token, not the map.
    cookie = scan.headers.get("Set-Cookie", "")
    assert len(cookie) < 1000, "session cookie is carrying the result map again"

    resp = client.post(
        "/send",
        data={"selected_sites": ["deep_0", "deep_119"],
              "user_name": "Jane Doe", "csrf_token": csrf_token},
    )
    assert resp.status_code == 200
    assert b"https://example-119.com/jane-doe-profile-page" in resp.data


def test_expired_results_ask_for_a_rescan_rather_than_failing_silently(
    client, csrf_token, monkeypatch
):
    _patch_scan(monkeypatch, results=[
        {"id": "deep_0", "title": "P", "url": "https://example.com/a", "snippet": ""}])
    client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    app_module.result_store.store.clear()  # simulate expiry

    resp = client.post(
        "/send",
        data={"selected_sites": "deep_0", "user_name": "Jane", "csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"expired" in resp.data


def test_broker_selection_works_without_any_stored_scan(client, csrf_token):
    # Broker checklist ids resolve from the registry, so they must not require
    # a scan to have run first.
    app_module.result_store.store.clear()
    resp = client.post(
        "/send",
        data={"selected_sites": "broker_spokeo", "user_name": "Jane Doe",
              "csrf_token": csrf_token},
    )
    assert resp.status_code == 200
    assert b"Generated petitions" in resp.data


# --- Static pages -----------------------------------------------------------
def test_about_page_links_the_creator(client):
    resp = client.get("/about")
    assert resp.status_code == 200
    assert b"https://github.com/Codex-Crusader" in resp.data
    assert b"https://codex-crusader.github.io/" in resp.data


def test_every_page_shares_the_same_navigation(client):
    # All four views extend base.html, so a nav link added in one place appears
    # everywhere. This catches a page that quietly stops extending it.
    for path in ("/", "/dashboard", "/legal", "/about"):
        body = client.get(path).data
        for link in (b'href="/"', b'href="/dashboard"', b'href="/legal"', b'href="/about"'):
            assert link in body, f"{link!r} missing from {path}"


def test_external_links_are_rel_protected(client):
    # window.opener access and referrer leakage, on a page whose whole purpose
    # is privacy.
    import re as _re

    for path in ("/about", "/legal", "/"):
        html = client.get(path).data.decode()
        for anchor in _re.findall(r'<a\b[^>]*target="_blank"[^>]*>', html):
            assert 'rel="noopener noreferrer"' in anchor, f"{anchor} on {path}"


def test_no_inline_script_or_style_survives_the_csp(client):
    # The CSP allows script-src/style-src 'self' only, so an inline script or a
    # style="..." attribute would silently not apply. Assert none creep in.
    for path in ("/", "/dashboard", "/legal", "/about"):
        html = client.get(path).data.decode().lower()
        assert "<script" not in html, path
        assert 'style="' not in html, path
