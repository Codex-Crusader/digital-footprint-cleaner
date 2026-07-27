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
| **Rate limiting** | Per-IP sliding-window limit on the search endpoint to curb abuse of the upstream search service. |
| **Input validation** | User input is trimmed and length-limited before use. |
| **Referrer leakage** | `Referrer-Policy: strict-origin-when-cross-origin`. |

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
