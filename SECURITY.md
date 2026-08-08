# Security Policy

## Reporting a vulnerability

If you discover a security issue, please **do not open a public issue**.
Instead, open a private security advisory via the repository's
**Security → Advisories** tab, or contact the maintainer directly. We aim to
acknowledge reports within a few days.

## Built-in protections

The application applies defence-in-depth by default:

| Area | Protection |
|------|-----------|
| **CSRF** | Every `POST` requires a per-session token, compared in constant time (`hmac.compare_digest`). Requests without a valid token are rejected with `400`. |
| **XSS** | Jinja2 autoescaping is on; result URLs are validated to be `http`/`https` only, blocking `javascript:`/`data:` URI injection. All page styling is served from a static file so a strict CSP can forbid inline scripts and styles. |
| **Clickjacking** | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`. |
| **MIME sniffing** | `X-Content-Type-Options: nosniff`. |
| **Content Security Policy** | `default-src 'self'`; no inline JS/CSS, no third-party origins. |
| **Session cookies** | `HttpOnly`, `SameSite=Lax`, and `Secure` (configurable for HTTPS). |
| **Secret key** | Sourced from the `SECRET_KEY` environment variable; a random ephemeral key is used only as a last resort, with a warning. |
| **Request size** | `MAX_CONTENT_LENGTH` (64 KB) rejects oversized bodies. |
| **Rate limiting** | Per-IP sliding-window limit, counted in **tokens rather than requests**. Endpoints that fan out into many upstream calls are charged accordingly (broker sweep 8, username check 12, email check 3, plain search 1), so a client cannot drain the upstream provider's quota with a handful of clicks. The username cost is derived from the platform registry at import, not hardcoded, so it cannot drift below the real fan-out. |
| **Input validation** | User input is trimmed and length-limited before use. Usernames are restricted to `[A-Za-z0-9][A-Za-z0-9._-]*` and URL-encoded before interpolation, so a handle cannot alter a probe's request target. |
| **Referrer leakage** | `Referrer-Policy: strict-origin-when-cross-origin`. |
| **Third-party data** | Gravatar profile fields are attacker-influenced: anyone can put arbitrary text and links in their own public profile. Text is Jinja-autoescaped; URLs are validated before being rendered, and an account whose URL fails validation is still disclosed but without a clickable link. |
| **No remote assets** | Avatars and third-party images are linked, never embedded. Viewing a report therefore does not announce the user's IP to Gravatar, GitHub, or any platform being checked. |
| **PII in logs** | Email addresses are never logged at INFO or above. Probe failures log a static label and the exception *type* only, because several `httpx` exceptions stringify with the full request URL. |
| **Outbound requests** | Every probe carries an explicit per-request timeout, redirects are not followed, and batches run under an overall wall-clock budget, so a slow or hostile host cannot pin a worker. |

## Access control

**Host-header allowlist (always on).** The app refuses any request whose `Host`
header is not `localhost`, `127.0.0.1` or `::1` (extend with
`DFC_ALLOWED_HOSTS`). Binding to loopback is not isolation on its own: a browser
will resolve an attacker-controlled hostname to 127.0.0.1 and then treat
whatever answers as same-origin. That is DNS rebinding, and CSRF tokens do not
stop it, because the rebound page can read the token out of the response it just
fetched. Checking the Host header does stop it.

**Passcode lock (optional).** Set `DFC_PASSCODE` or `DFC_PASSCODE_HASH` and every
page requires a login first:

- PBKDF2-HMAC-SHA256, 600,000 rounds, 16-byte per-install random salt.
- Constant-time comparison, so no timing signal.
- Login attempts throttled per client address; a lockout refuses the correct
  passcode too, so it cannot be sidestepped by guessing right on the next try.
- The session is rotated on login, so a token captured before authenticating
  cannot be replayed as an authenticated one.
- Sliding idle timeout (`DFC_IDLE_TIMEOUT`, default 30 minutes).
- A malformed stored hash, or a tampered session timestamp, fails closed.

It is opt-in rather than mandatory: the host check already covers the remote
attacker, and a tool that demands credential setup before it runs once is a tool
people stop using. When no passcode is set, the header says **Unlocked** rather
than letting the user assume a protection that is not there.

## Local data storage

The removal tracker (`/dashboard`) writes to a local SQLite database at
`instance/tracker.sqlite3` (override with `DFC_DB_PATH`).

* It stores site names, request status, and the user's own notes. It does **not**
  store search results or scan output.
* That is still sensitive: it is a record of someone's exposure and their
  attempts to reduce it: so the file is gitignored twice over (`instance/` and
  `*.sqlite3`) and never leaves the machine.
* The dashboard exposes a one-click **Delete All Tracked Requests** action.
* All SQL uses bound parameters. Each call opens and closes its own connection,
  so no connection is shared across Flask worker threads.

## Deployment notes

* Always set a strong `SECRET_KEY` in production.
* Serve over HTTPS and set `SESSION_COOKIE_SECURE=true`.
* Do **not** run with `FLASK_ENV=development` in production (it enables the
  interactive debugger, which allows remote code execution).
* Run behind a production WSGI server (e.g. gunicorn/waitress), not the
  built-in development server.
* The in-memory rate limiter is per-process. Behind multiple workers, use a
  shared store (e.g. Redis) or an edge rate limiter. If running behind a
  reverse proxy, configure `ProxyFix` so `remote_addr` reflects the real client.

## Supported versions

This is an educational project; only the latest `main` branch is supported.
