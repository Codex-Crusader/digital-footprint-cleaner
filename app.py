"""Digital Footprint Cleaner -- Flask web application.

A small, privacy-first tool that searches for a person's public footprint and
generates data-removal petitions. Security controls live here so the whole app
stays easy to audit in one place:

* CSRF protection on every POST (session token, constant-time comparison).
* Security response headers (CSP, anti-clickjacking, no-sniff, etc.).
* Hardened session cookies (HttpOnly, SameSite, optional Secure).
* Request-size limit and per-IP rate limiting on the search endpoint.
* Secret key sourced from the environment.

Run with ``python app.py`` (see README for configuration).
"""

import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import analysis
from scanner import SearchError, find_footprint
from utils import petition_writer
from utils.validation import MAX_NAME_LENGTH, MAX_QUERY_LENGTH, clamp_text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _bool_env(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


DEBUG_MODE = os.getenv("FLASK_ENV", "production").lower() == "development"

app = Flask(__name__)

# --- Secret key -------------------------------------------------------------
# Prefer an explicit SECRET_KEY so sessions survive restarts. Fall back to a
# random ephemeral key for zero-config local use, but warn loudly.
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(32)
    logger.warning(
        "SECRET_KEY is not set; using a random ephemeral key. Sessions will "
        "reset on restart. Set SECRET_KEY in any real deployment."
    )
app.secret_key = _secret

# --- Hardened configuration -------------------------------------------------
app.config.update(
    MAX_CONTENT_LENGTH=64 * 1024,  # reject oversized request bodies (DoS guard)
    SESSION_COOKIE_HTTPONLY=True,  # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",  # mitigates cross-site request inclusion
    # Enable Secure cookies over HTTPS in production. Configurable so local
    # HTTP development still works.
    SESSION_COOKIE_SECURE=_bool_env("SESSION_COOKIE_SECURE", default=False),
)

# --- Simple in-memory rate limiter -----------------------------------------
# Per-process and per-IP; good enough for the dev server and a single worker.
# For multi-worker production, place a shared limiter (e.g. Redis) in front.
SEARCH_RATE_LIMIT = int(os.getenv("SEARCH_RATE_LIMIT", "10"))
SEARCH_RATE_WINDOW = int(os.getenv("SEARCH_RATE_WINDOW", "60"))  # seconds
_rate_lock = threading.Lock()
_rate_hits: "defaultdict[str, deque]" = defaultdict(deque)


def _is_rate_limited(client_ip: str) -> bool:
    """Return True if ``client_ip`` has exceeded the search rate limit."""
    now = time.time()
    with _rate_lock:
        hits = _rate_hits[client_ip]
        cutoff = now - SEARCH_RATE_WINDOW
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= SEARCH_RATE_LIMIT:
            return True
        hits.append(now)
        return False


def reset_rate_limiter():
    """Clear all recorded request timestamps. Public hook used by tests."""
    with _rate_lock:
        _rate_hits.clear()


# --- CSRF protection --------------------------------------------------------
@app.before_request
def csrf_protect():
    """Issue a per-session CSRF token and validate it on every POST."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        submitted = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, submitted):
            logger.warning("Rejected POST with missing/invalid CSRF token.")
            abort(400, description="Invalid or missing CSRF token.")


@app.context_processor
def inject_csrf_token():
    """Expose ``csrf_token()`` to templates for embedding in forms."""
    return {"csrf_token": lambda: session.get("csrf_token", "")}


# --- Security response headers ---------------------------------------------
@app.after_request
def set_security_headers(response):
    """Attach defense-in-depth security headers to every response."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    """Homepage: search form plus results/petition rendering."""
    results = []
    report = None
    user_info = ""
    location = ""
    error = None
    searched = False

    if request.method == "POST":
        user_info = clamp_text(request.form.get("user_info", ""), MAX_QUERY_LENGTH)
        location = clamp_text(request.form.get("location", ""), MAX_QUERY_LENGTH)
        searched = True
        if not user_info:
            error = "Please provide your name or email to search."
        elif _is_rate_limited(request.remote_addr or "unknown"):
            error = "Too many searches. Please wait a moment and try again."
            logger.warning("Rate limit hit for %s", request.remote_addr)
        else:
            try:
                results = find_footprint(user_info, location=location or None)
                report = analysis.analyze(results)
                session["result_map"] = {item["id"]: item["url"] for item in results}
            except ValueError:
                error = "Please provide your name or email to search."
            except SearchError:
                error = "The search service is temporarily unavailable. Please try again shortly."
            except Exception as exc:  # noqa: BLE001 - last-resort safety net
                error = "There was an error processing your request."
                logger.error("Unexpected error in find_footprint: %s", exc)

    return render_template(
        "index.html",
        results=results,
        report=report,
        brokers=analysis.all_brokers(),
        user_info=user_info,
        location=location,
        error=error,
        searched=searched,
        petitions=None,
    )


@app.route("/send", methods=["POST"])
def send():
    """Generate removal petitions for the sites the user selected."""
    selected_ids = request.form.getlist("selected_sites")
    user_name = clamp_text(request.form.get("user_name", ""), MAX_NAME_LENGTH)
    result_map = session.get("result_map", {})

    if not selected_ids:
        flash("No sites selected. Please select at least one site.", "warning")
        return redirect(url_for("index"))

    if not isinstance(result_map, dict):
        flash("Your session expired. Please run the search again.", "danger")
        return redirect(url_for("index"))

    try:
        petitions = petition_writer.send_petitions(
            selected_ids, result_map, user_name or petition_writer.DEFAULT_NAME
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error generating petitions: %s", exc)
        flash("An error occurred while generating petitions.", "danger")
        return redirect(url_for("index"))

    if not petitions:
        flash("No valid petitions could be generated for your selection.", "warning")
        return redirect(url_for("index"))

    flash(f"Generated {len(petitions)} petition(s) below.", "success")
    return render_template(
        "index.html",
        results=[],
        report=None,
        brokers=analysis.all_brokers(),
        user_info="",
        location="",
        error=None,
        searched=False,
        petitions=petitions,
    )


@app.route("/legal")
def legal():
    """Display the legal information page."""
    return render_template("legal.html")


if __name__ == "__main__":
    # Debug mode is opt-in via FLASK_ENV=development and must stay off in prod.
    app.run(debug=DEBUG_MODE)
