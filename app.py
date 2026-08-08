"""Digital Footprint Cleaner: Flask web application.

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

# Flask is declared in both pyproject.toml ([project] dependencies) and
# requirements.txt. PyCharm's package inspection does not pick either up in this
# project, see the note in pyproject.toml, so the check is suppressed rather
# than left as a standing false positive.
# noinspection PyPackageRequirements
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
import scanner
from utils import (
    auth,
    email_signals,
    petition_writer,
    result_store,
    search_plan,
    tracker,
    username_check,
)
from utils.identity import IdentityProfile
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
# Budget is counted in tokens, not requests: see _is_rate_limited. A plain
# search costs 1, but the fan-out endpoints cost roughly one token per upstream
# request they make, so the default allowance is sized for a realistic session
# (one deep scan, one broker sweep, one email check, one username check).
#
# The allowance grew with the deep scan: a "deep" plan is around 17 upstream
# searches on its own, and the old budget of 30 would have left no room for the
# broker sweep that naturally follows it. Sized from the endpoint costs below
# rather than picked round.
SEARCH_RATE_LIMIT = int(os.getenv("SEARCH_RATE_LIMIT", "70"))
SEARCH_RATE_WINDOW = int(os.getenv("SEARCH_RATE_WINDOW", "60"))  # seconds
_rate_lock = threading.Lock()
_rate_hits: "defaultdict[str, deque]" = defaultdict(deque)


def _is_rate_limited(client_ip: str, cost: int = 1) -> bool:
    """Return True if ``client_ip`` has exceeded the search rate limit.

    ``cost`` is how many tokens this request consumes. It exists because the
    endpoints are no longer equal: one plain search is a single backend call,
    but a broker sweep or a username check fans out into many. Charging them
    all one token would let a client burn the upstream provider's quota in a
    couple of clicks: after which every user gets throttled results.
    """
    now = time.time()
    cost = max(1, int(cost))
    with _rate_lock:
        hits = _rate_hits[client_ip]
        cutoff = now - SEARCH_RATE_WINDOW
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) + cost > SEARCH_RATE_LIMIT:
            return True
        hits.extend([now] * cost)
        return False


def reset_rate_limiter():
    """Clear all recorded request timestamps. Public hook used by tests."""
    with _rate_lock:
        _rate_hits.clear()


# --- Access control ----------------------------------------------------------
# Computed once at import so a passcode change requires a restart, and so the
# PBKDF2 derivation of DFC_PASSCODE is not paid on every request.
PASSCODE_HASH = auth.configured_hash()
LOCK_ENABLED = bool(PASSCODE_HASH)
_login_throttle = auth.LoginThrottle()

# Endpoints reachable without unlocking. Kept minimal and explicit: an
# allowlist fails closed, so a route added later is protected by default rather
# than exposed by an oversight.
_PUBLIC_ENDPOINTS = frozenset({"login", "static"})

if not LOCK_ENABLED:
    logger.warning(
        "No passcode configured. Anyone with access to this machine can open "
        "the app. Set DFC_PASSCODE (or DFC_PASSCODE_HASH) to require one."
    )


def reset_login_throttle():
    """Clear recorded login attempts. Public hook used by tests."""
    _login_throttle.reset()


@app.before_request
def reject_foreign_hosts():
    """Refuse requests that are not addressed to this machine.

    Bound to loopback, this app is still reachable from any page the user has
    open: a browser will resolve an attacker-controlled hostname to 127.0.0.1
    and then treat the app as same-origin, which is DNS rebinding. CSRF tokens
    do not help there, because the rebound page can read the token out of the
    response it just fetched.

    Checking the Host header closes it. Browsers send the hostname the user
    actually navigated to, so a rebound request arrives naming the attacker's
    domain and never reaches a route.
    """
    if not auth.host_is_allowed(request.headers.get("Host")):
        logger.warning("Refused request with unexpected Host header.")
        abort(403, description="This app only answers requests addressed to localhost.")


@app.before_request
def require_unlock():
    """Gate every non-public endpoint behind the passcode, when one is set."""
    if not LOCK_ENABLED or request.endpoint in _PUBLIC_ENDPOINTS:
        return None
    if auth.session_is_fresh(session.get("unlocked_at")):
        # Sliding expiry: activity keeps the session alive, idleness ends it.
        session["unlocked_at"] = time.time()
        return None
    session.pop("unlocked_at", None)
    return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Unlock the app with the configured passcode."""
    if not LOCK_ENABLED:
        return redirect(url_for("index"))
    if auth.session_is_fresh(session.get("unlocked_at")):
        return redirect(url_for("index"))

    client = request.remote_addr or "unknown"
    error = None

    if request.method == "POST":
        if _login_throttle.is_locked_out(client):
            wait = _login_throttle.seconds_remaining(client)
            error = f"Too many attempts. Try again in {wait} second(s)."
        elif auth.verify_passcode(request.form.get("passcode", ""), PASSCODE_HASH):
            _login_throttle.record_success(client)
            # Rotate the session on privilege change so a token captured before
            # the login cannot be replayed as an authenticated one.
            csrf = session.get("csrf_token")
            session.clear()
            session["csrf_token"] = csrf or secrets.token_urlsafe(32)
            session["unlocked_at"] = time.time()
            logger.info("Unlocked by %s", client)
            return redirect(_safe_next(request.args.get("next")))
        else:
            _login_throttle.record_failure(client)
            logger.warning("Failed unlock attempt from %s", client)
            error = "Incorrect passcode."

    return render_template("login.html", error=error, active_page="login")


def _safe_next(target: object) -> str:
    """Return a safe same-site redirect target, defaulting to the home page.

    Only a path beginning with a single ``/`` is accepted. ``//evil.example``
    is a protocol-relative URL that browsers treat as absolute, so the usual
    "starts with /" check alone is an open-redirect.
    """
    if isinstance(target, str) and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("index")


@app.route("/lock", methods=["POST"])
def lock():
    """End the session immediately."""
    session.pop("unlocked_at", None)
    flash("Locked. Enter the passcode to continue.", "success")
    return redirect(url_for("login") if LOCK_ENABLED else url_for("index"))


@app.context_processor
def inject_protection_state():
    """Expose the lock state so the UI can be honest about what protects it."""
    state, explanation = auth.describe_protection(LOCK_ENABLED)
    return {
        "lock_enabled": LOCK_ENABLED,
        "protection_state": state,
        "protection_explanation": explanation,
    }


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


# How many rate-limit tokens each fan-out endpoint costs. Roughly one token
# per upstream request the endpoint can make.
BROKER_SWEEP_COST = scanner.BROKER_CHECK_MAX
EMAIL_SIGNAL_COST = 3  # avatar + profile + GitHub search
# Derived from the platform registry rather than hardcoded: platforms marked
# unreliable are never requested, and a literal here silently undercharges as
# soon as the registry changes.
USERNAME_CHECK_COST = sum(
    1
    for platform in username_check.PLATFORMS
    if platform.signal != username_check.SIGNAL_UNRELIABLE
)


def _remember_results(results):
    """Store the id-to-URL map server-side and put only a token in the session.

    The map used to live in the session cookie itself, which held ten results
    comfortably and a deep scan's hundred-plus not at all: see
    :mod:`utils.result_store` for what that silently broke.
    """
    token = result_store.store.put(
        {item["id"]: item["url"] for item in results},
        token=session.get("results_token"),
    )
    session["results_token"] = token


def _render_index(**overrides):
    """Render the single-page UI with every template variable defaulted.

    Jinja renders an undefined name as empty rather than raising, so a route
    that forgets one of these kwargs would silently show a blank section. One
    defaults dict means a new template variable cannot be half-wired.

    Covers ``index.html`` only. ``dashboard.html`` is rendered directly by the
    dashboard routes; if a second route ever renders it, give it the same
    treatment rather than passing kwargs by hand.
    """
    context = {
        "results": [],
        "report": None,
        "coverage": None,
        "brokers": analysis.all_brokers(),
        "profile": IdentityProfile(),
        "depth": search_plan.DEFAULT_DEPTH,
        "depths": search_plan.depth_choices(),
        "user_info": "",
        "location": "",
        "error": None,
        "petitions": None,
        "broker_checks": None,
        "signals": None,
        "username_results": None,
        "username_query": "",
        "legal_bases": petition_writer.available_legal_bases(),
        "data_types": petition_writer.available_data_types(),
    }
    context.update(overrides)
    return render_template("index.html", **context)


def _coverage_summary(report):
    """Turn a :class:`scanner.DeepSearchReport` into template-friendly data.

    Coverage is reported as prominently as the results themselves. A deep scan
    makes many requests and some routinely fail; if the page showed only what
    was found, a half-throttled sweep would read exactly like a clean bill of
    health. Telling the user "11 of 17 checks completed" is the difference
    between an honest tool and a reassuring one.
    """
    groups: "dict[str, list[dict]]" = {}
    for outcome in report.outcomes:
        groups.setdefault(outcome.group, []).append(
            {
                "key": outcome.key,
                "label": outcome.label,
                "status": outcome.status,
                "count": outcome.count,
                "detail": outcome.detail,
            }
        )
    return {
        "groups": [{"key": key, "passes": passes} for key, passes in groups.items()],
        "completed": report.completed_passes,
        "total": report.total_passes,
        "failed": report.failed_passes,
        "partial": report.partial,
        "complete": report.complete,
    }


@app.route("/", methods=["GET", "POST"])
def index():
    """Homepage: search form plus results/petition rendering."""
    profile = IdentityProfile()
    report = None
    coverage = None
    depth = search_plan.DEFAULT_DEPTH
    error = None
    results = []

    if request.method == "POST":
        profile = IdentityProfile.from_form(request.form)
        depth = search_plan.resolve_depth(request.form.get("depth"))

        # Charged at the size of the plan about to run, derived from the plan
        # itself. A hardcoded number silently undercharges the moment a depth
        # tier gains a pass: the same reasoning as USERNAME_CHECK_COST.
        cost = search_plan.plan_size(profile, depth)

        if not profile.has_name:
            error = "Please provide a name to search for."
        elif _is_rate_limited(request.remote_addr or "unknown", cost=max(1, cost)):
            error = "Too many searches. Please wait a moment and try again."
            logger.warning("Rate limit hit for %s", request.remote_addr)
        else:
            try:
                scan = scanner.deep_search(profile, depth=depth)
            except ValueError:
                error = "Please provide a name to search for."
            except Exception as exc:  # noqa: BLE001 - last-resort safety net
                error = "There was an error processing your request."
                logger.error("Unexpected error in deep_search: %s", type(exc).__name__)
                logger.debug("Deep search failure detail", exc_info=True)
            else:
                # deep_search never raises for a backend problem: individual
                # passes fail into the coverage report instead, so a partly
                # throttled sweep still shows what it did find.
                results = scan.results
                report = analysis.analyze(results, profile=profile)
                coverage = _coverage_summary(scan)
                _remember_results(results)
                # Remembered so the broker sweep can reuse it without asking
                # the user to retype their name.
                session["last_query"] = profile.core_name or profile.full_name

    return _render_index(
        results=results,
        report=report,
        coverage=coverage,
        profile=profile,
        depth=depth,
        user_info=profile.full_name,
        location=profile.location,
        error=error,
    )


@app.route("/check-brokers", methods=["POST"])
def check_brokers():
    """Run site-scoped searches against the broker registry.

    This is the deep check the plain scan cannot do: a general web search
    rarely ranks people-search listing pages, so each broker gets its own
    ``site:`` query.
    """
    # A *blank* field is an explicit empty request and must not silently fall
    # back to whatever was searched earlier: that would send a previous name
    # or email to 8 brokers without the user asking. Only an entirely absent
    # field reuses the last scan, which is the "scan, then deep check" flow.
    submitted = request.form.get("user_info")
    if submitted is None:
        user_info = clamp_text(session.get("last_query", ""), MAX_QUERY_LENGTH)
    else:
        user_info = clamp_text(submitted, MAX_QUERY_LENGTH)

    if not user_info:
        flash("Run a scan first, or enter your name, so we know what to check for.",
              "warning")
        return redirect(url_for("index"))

    # Charged at the number of upstream searches it can trigger, not one.
    if _is_rate_limited(request.remote_addr or "unknown", cost=BROKER_SWEEP_COST):
        flash("Too many searches. Please wait a moment and try again.", "warning")
        return redirect(url_for("index"))

    try:
        checks = scanner.check_brokers(user_info, analysis.all_brokers())
    except ValueError:
        flash("Please provide your name to check the broker list.", "warning")
        return redirect(url_for("index"))
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        logger.error("Unexpected error during broker sweep: %s", exc)
        flash("There was an error checking the data brokers.", "danger")
        return redirect(url_for("index"))

    listed = sum(1 for c in checks if c["status"] == "listed")
    unknown = sum(1 for c in checks if c["status"] == "unknown")
    if listed:
        flash(f"Found {listed} confirmed broker listing(s).", "danger")
    elif unknown:
        flash("No listings confirmed, but some checks could not complete.", "warning")
    else:
        flash("No broker listings found in the sites we were able to check.", "success")

    return _render_index(user_info=user_info, broker_checks=checks)


def _broker_by_id(broker_id):
    """Look up a broker registry entry by its bare ID."""
    return next((b for b in analysis.all_brokers() if b.get("id") == broker_id), None)


@app.route("/send", methods=["POST"])
def send():
    """Generate removal petitions for the sites the user selected."""
    selected_ids = request.form.getlist("selected_sites")
    user_name = clamp_text(request.form.get("user_name", ""), MAX_NAME_LENGTH)
    data_types = request.form.getlist("data_types")
    legal_basis = clamp_text(request.form.get("legal_basis", ""), 50)
    result_map = result_store.store.get(session.get("results_token"))

    if not selected_ids:
        flash("No sites selected. Please select at least one site.", "warning")
        return redirect(url_for("index"))

    # Broker checklist entries carry their own ``broker_<id>`` identifiers and
    # are resolved from the registry, so they work with no stored scan at all.
    # Only a selection referring to scan results needs the map.
    needs_results = any(not sid.startswith("broker_") for sid in selected_ids)
    if needs_results and not result_map:
        flash("Your scan results have expired. Please run the search again.", "warning")
        return redirect(url_for("index"))

    try:
        petitions = petition_writer.send_petitions(
            selected_ids,
            result_map,
            user_name or petition_writer.DEFAULT_NAME,
            data_types=data_types,
            legal_basis=legal_basis or petition_writer.DEFAULT_LEGAL_BASIS,
            broker_lookup=analysis.broker_for,
            broker_by_id=_broker_by_id,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Error generating petitions: %s", exc)
        flash("An error occurred while generating petitions.", "danger")
        return redirect(url_for("index"))

    if not petitions:
        flash("No valid petitions could be generated for your selection.", "warning")
        return redirect(url_for("index"))

    flash(f"Generated {len(petitions)} petition(s) below.", "success")
    return _render_index(petitions=petitions)


@app.route("/signals", methods=["POST"])
def signals():
    """Check what an email address alone reveals publicly."""
    email = clamp_text(request.form.get("email", ""), MAX_QUERY_LENGTH)
    if not email:
        flash("Enter an email address to check.", "warning")
        return redirect(url_for("index"))

    if _is_rate_limited(request.remote_addr or "unknown", cost=EMAIL_SIGNAL_COST):
        flash("Too many checks. Please wait a moment and try again.", "warning")
        return redirect(url_for("index"))

    try:
        result = email_signals.gather_email_signals(email)
    except ValueError:
        flash("That does not look like a valid email address.", "warning")
        return redirect(url_for("index"))
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        # Type only: the exception text can embed the request URL, and for these
        # probes that URL carries the email address being checked.
        logger.error("Unexpected error gathering email signals: %s", type(exc).__name__)
        logger.debug("Email signal failure detail", exc_info=True)
        flash("There was an error checking that address.", "danger")
        return redirect(url_for("index"))

    if result["summary"]["partial"]:
        flash("Some checks could not complete; those are marked 'unknown' below.",
              "warning")
    return _render_index(signals=result)


@app.route("/username", methods=["POST"])
def username():
    """Check which platforms have a public profile under a username."""
    handle = clamp_text(request.form.get("username", ""), MAX_NAME_LENGTH)
    if not handle:
        flash("Enter a username to check.", "warning")
        return redirect(url_for("index"))

    if _is_rate_limited(request.remote_addr or "unknown", cost=USERNAME_CHECK_COST):
        flash("Too many checks. Please wait a moment and try again.", "warning")
        return redirect(url_for("index"))

    try:
        results = username_check.check_username(handle)
    except ValueError:
        flash("Usernames may only contain letters, numbers, dots, dashes and "
              "underscores.", "warning")
        return redirect(url_for("index"))
    except Exception as exc:  # noqa: BLE001 - last-resort safety net
        logger.error("Unexpected error checking username: %s", type(exc).__name__)
        logger.debug("Username check failure detail", exc_info=True)
        flash("There was an error checking that username.", "danger")
        return redirect(url_for("index"))

    return _render_index(username_results=results, username_query=handle)


# --- Removal-request dashboard ----------------------------------------------


@app.route("/dashboard")
def dashboard():
    """Show tracked removal requests and their status."""
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        requests=tracker.list_requests(),
        stats=tracker.summary(),
        statuses=tracker.STATUSES,
        brokers=analysis.all_brokers(),
    )


@app.route("/dashboard/add", methods=["POST"])
def dashboard_add():
    """Start tracking a removal request."""
    site_name = clamp_text(request.form.get("site_name", ""), MAX_NAME_LENGTH)
    if not site_name:
        flash("Pick a site to track.", "warning")
        return redirect(url_for("dashboard"))

    broker = _broker_by_id(clamp_text(request.form.get("broker_id", ""), 100))
    try:
        tracker.add_request(
            site_name,
            site_domain=(broker or {}).get("domain", ""),
            opt_out_url=(broker or {}).get("opt_out_url", ""),
            subject_label=clamp_text(request.form.get("subject_label", ""), 200),
            data_types=request.form.getlist("data_types"),
            legal_basis=clamp_text(request.form.get("legal_basis", ""), 50),
            notes=clamp_text(request.form.get("notes", ""), 500),
        )
    except ValueError as exc:
        logger.warning("Rejected tracker entry: %s", exc)
        flash("Could not add that entry.", "warning")
        return redirect(url_for("dashboard"))

    flash(f"Now tracking your request to {site_name}.", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard/update", methods=["POST"])
def dashboard_update():
    """Change the status or notes of a tracked request."""
    try:
        request_id = int(request.form.get("request_id", ""))
    except (TypeError, ValueError):
        flash("That entry no longer exists.", "warning")
        return redirect(url_for("dashboard"))

    if request.form.get("action") == "delete":
        tracker.delete_request(request_id)
        flash("Entry deleted.", "success")
        return redirect(url_for("dashboard"))

    status = clamp_text(request.form.get("status", ""), 50)
    try:
        updated = tracker.update_request(request_id, status=status or None)
    except ValueError:
        flash("Unknown status.", "warning")
        return redirect(url_for("dashboard"))

    flash("Status updated." if updated else "That entry no longer exists.",
          "success" if updated else "warning")
    return redirect(url_for("dashboard"))


@app.route("/dashboard/purge", methods=["POST"])
def dashboard_purge():
    """Delete every tracked request.

    Prominent by design: a tool that stores a record of someone's privacy work
    must offer a one-click way to destroy it.
    """
    removed = tracker.purge_all()
    flash(f"Deleted {removed} tracked request(s). Nothing is left on disk.",
          "success")
    return redirect(url_for("dashboard"))


@app.route("/legal")
def legal():
    """Display the legal information page."""
    return render_template("legal.html", active_page="legal")


@app.route("/about")
def about():
    """Display the about / creator page."""
    return render_template("about.html", active_page="about")


if __name__ == "__main__":
    # Debug mode is opt-in via FLASK_ENV=development and must stay off in prod.
    app.run(debug=DEBUG_MODE)
