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
    # confirm whether a broker actually lists them.
    assert b"duckduckgo.com/?q=site" in resp.data
    assert b"spokeo.com" in resp.data


def test_landing_page_has_no_check_links(client):
    # Before any search there is no name to scope a check to.
    resp = client.get("/")
    assert b"duckduckgo.com/?q=site" not in resp.data


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
    assert b"example.com/jane" in resp.data


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
