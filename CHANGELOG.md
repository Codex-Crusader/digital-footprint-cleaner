# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/).

## Author's note

This release is the product of a deep overhaul and hands-on research into how
personal information spreads across the web, especially through the data-broker
and people-search ecosystem. The work covered three fronts: making the tool
actually function, hardening it against common web vulnerabilities, and
reshaping it from a plain search wrapper into something that gives users
concrete, verified actions to reclaim their privacy.

A key research outcome was an honest one: general web search does **not**
reliably surface data-broker listing pages, so "scan and detect" alone is not
enough. That finding is what led to the curated, verified opt-out registry and
the proactive checklist, which are now the core of the tool.

Sorry for dumping 10 month long changes all at once on the repo. i forgor

## [1.0.0] 

First hardened, feature-complete release. This is a large overhaul of the
original prototype.

### Added

- **Footprint analysis engine** (`analysis.py`): every search result is
  classified into a category (data broker, public records, social media,
  professional, forums, news, reference, other) and the overall exposure is
  scored, with data-broker presence driving the risk band.
- **Verified data-broker opt-out registry** (`data/brokers.json`): 31 major US
  people-search sites with opt-out URLs verified against maintained public
  sources (July 2026).
- **Proactive opt-out checklist** in the UI, presented as the primary action.
- **Per-broker "Check" links**: after a scan, each broker gets a name-scoped
  search link so the user can confirm whether that site actually lists them.
- **Exposure report UI**: risk badge, summary stats, and results grouped by
  category.
- **On-screen petition generation**: generated removal petitions are now
  returned and displayed, ready to copy (previously printed to the console only).
- **Optional location field** to disambiguate common names.
- **Shared validation helpers** (`utils/validation.py`) for URL and input
  sanitisation.
- **Test suite** (`tests/`, 44 tests) covering validation, classification, risk
  scoring, broker detection, petition generation, the (mocked) search backend,
  and the security controls.
- **Developer tooling**: `requirements-dev.txt` (pytest, mypy, pyflakes,
  pycodestyle) and `pytest.ini`.
- **Documentation**: `SECURITY.md`, `.env.example`, status badges, and a
  rewritten `README.md` and `contributing.md`.

### Changed

- Migrated search from the deprecated `duckduckgo-search` package to the
  maintained `ddgs` package.
- Rebuilt the frontend into a clean, card-based UI with an external stylesheet.
- Secret key is now sourced from the `SECRET_KEY` environment variable, with a
  random ephemeral fallback for zero-config local use.
- Configuration (debug mode, cookie security, rate limits) is now driven by
  environment variables.
- File paths now use `pathlib` for clarity and correctness.

### Fixed

- Petition generation crashed on every use because it required a missing
  `data/services.json`; `load_services()` now degrades gracefully.
- Search results rendered a blank name due to a template field mismatch
  (`result.name` vs `result.title`).
- Flash messages were never displayed to the user; they now render.
- Empty or zero-result searches showed a blank page; they now show a clear
  message.
- Corrected an invalid dependency name in `requirements.txt`
  (`beautifulsoup` -> `beautifulsoup4`).

### Security

- **CSRF protection** on every `POST` (per-session token, constant-time
  comparison; invalid requests rejected with HTTP 400).
- **Content Security Policy** with no inline scripts or styles and no
  third-party origins.
- **Anti-clickjacking**: `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`.
- **MIME-sniffing protection**, `Referrer-Policy`, and `Permissions-Policy`
  headers.
- **Hardened session cookies**: `HttpOnly`, `SameSite=Lax`, and optional
  `Secure` for HTTPS.
- **URL validation**: only `http`/`https` result links are rendered, blocking
  `javascript:` and `data:` URI injection; external links use
  `rel="noopener noreferrer"`.
- **Request-size limit** (`MAX_CONTENT_LENGTH`) and **per-IP rate limiting** on
  the search endpoint.
- Debug mode is opt-in via `FLASK_ENV=development` and off by default.

### Removed

- Stopped tracking a committed runtime cache (`vqd_cache/cache.db`) and added it
  to `.gitignore`.
- Removed the deprecated `duckduckgo-search` dependency.

## [0.1.0] - Prototype

- Initial prototype: single DuckDuckGo search, console-printed petitions, and a
  basic legal page.
