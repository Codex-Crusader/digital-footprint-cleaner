# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

import app as app_module


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
    monkeypatch.setattr(app_module, "find_footprint", lambda *_args, **_kwargs: [])
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert resp.status_code == 200


# --- Search flow ------------------------------------------------------------
def test_empty_input_shows_prompt(client, csrf_token):
    resp = client.post("/", data={"user_info": "   ", "csrf_token": csrf_token})
    assert resp.status_code == 200
    assert b"Please provide your name or email" in resp.data


def test_no_results_message(client, csrf_token, monkeypatch):
    monkeypatch.setattr(app_module, "find_footprint", lambda *_args, **_kwargs: [])
    resp = client.post("/", data={"user_info": "Nobody", "csrf_token": csrf_token})
    assert b"No web results found" in resp.data


def test_search_error_shows_friendly_message(client, csrf_token, monkeypatch):
    def boom(*_args, **_kwargs):
        raise app_module.SearchError("down")

    monkeypatch.setattr(app_module, "find_footprint", boom)
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert b"temporarily unavailable" in resp.data


def test_broker_result_shows_exposure_and_opt_out(client, csrf_token, monkeypatch):
    monkeypatch.setattr(
        app_module,
        "find_footprint",
        lambda *_args, **_kwargs: [
            {
                "id": "duck_0",
                "title": "Jane Doe - Spokeo",
                "url": "https://www.spokeo.com/Jane-Doe",
                "snippet": "address, phone",
            }
        ],
    )
    resp = client.post("/", data={"user_info": "Jane Doe", "csrf_token": csrf_token})
    assert b"exposure" in resp.data
    assert b"data brokers" in resp.data
    assert b"https://www.spokeo.com/optout" in resp.data  # verified opt-out link


def test_broker_checklist_shows_scoped_check_link_after_scan(client, csrf_token, monkeypatch):
    monkeypatch.setattr(app_module, "find_footprint", lambda *_args, **_kwargs: [])
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
    monkeypatch.setattr(
        app_module,
        "find_footprint",
        lambda *_args, **_kwargs: [
            {
                "id": "duck_0",
                "title": "Profile",
                "url": "https://example.com/jane",
                "snippet": "bio",
            }
        ],
    )
    resp = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
    assert b'rel="noopener noreferrer"' in resp.data
    assert b"https://example.com/jane" in resp.data


# --- Send flow --------------------------------------------------------------
def test_send_renders_generated_petitions(client, csrf_token, monkeypatch):
    monkeypatch.setattr(
        app_module,
        "find_footprint",
        lambda *_args, **_kwargs: [
            {
                "id": "duck_0",
                "title": "Profile",
                "url": "https://example.com/jane",
                "snippet": "",
            }
        ],
    )
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
    assert b"Generated Petitions" in resp.data
    assert b"https://example.com/jane" in resp.data


def test_send_with_no_selection_redirects(client, csrf_token):
    resp = client.post("/send", data={"csrf_token": csrf_token})
    assert resp.status_code == 302


# --- Rate limiting ----------------------------------------------------------
def test_search_is_rate_limited(client, csrf_token, monkeypatch):
    monkeypatch.setattr(app_module, "find_footprint", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(app_module, "SEARCH_RATE_LIMIT", 3)
    # First 3 succeed, the 4th is blocked.
    for _ in range(3):
        ok = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
        assert b"Too many searches" not in ok.data
    blocked = client.post("/", data={"user_info": "Jane", "csrf_token": csrf_token})
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
    monkeypatch.setattr(app_module, "find_footprint", lambda *_a, **_k: [])
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
    monkeypatch.setattr(app_module, "find_footprint", lambda *_a, **_k: [])
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
    assert b"Generated Petitions" in resp.data
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
