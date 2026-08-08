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

## [1.1.0]

Delivers the whole 1.0 roadmap, and attacks the limitation that release was
honest about: general web search does not rank data-broker listing pages.

### Added

- **Data-broker deep check** (`scanner.check_broker` / `check_brokers`): one
  site-scoped `site:<domain> "<name>"` search per broker, which finds listing
  pages the broad scan misses. Bounded by a concurrency cap, an overall
  wall-clock budget, and a 15-minute cache, because the search backend
  throttles. Brokers not reached are reported as `skipped`, never as "clean".
  A result only counts when the matching page is actually *hosted on* the
  broker's domain, so pages that merely mention a broker cannot produce a false
  "you are listed".
- **Email signals** (`utils/email_signals.py`): checks whether an address has a
  Gravatar avatar, reads its public Gravatar profile (real name, location, job
  title, employer, and linked social accounts), and searches GitHub for
  accounts registered to it. Optional `GITHUB_TOKEN` raises the search limit.
- **Username presence check** (`utils/username_check.py`): looks for public
  profile pages across 17 platforms. Platforms that answer unreliably
  (Instagram, X, TikTok, Twitch, Tumblr all return HTTP 200 for every handle)
  are not requested at all rather than guessed at.
- **Customisable petitions**: the legal basis (GDPR Art. 17, CCPA/CPRA, India's
  DPDP Act 2023, or a neutral request) and the exact data types to erase are now
  selectable. Each petition cites the correct statute and its response deadline.
  Building blocks live in `data/petition_templates.json`.
- **Removal-request tracker** (`utils/tracker.py`, `/dashboard`): a local
  SQLite record of who was contacted, the request's status through a six-state
  lifecycle (including `reappeared`, since broker data comes back), and the
  user's own notes. Includes a one-click purge.
- **Petitions for brokers from the checklist**: broker entries can now be
  selected directly, addressed by name and citing their published opt-out page.
- `pyproject.toml` (project metadata, dependency list, mypy config) and
  `setup.cfg` (pycodestyle config, which cannot read pyproject.toml).

### Changed

- **Rate limiting is now cost-weighted.** Endpoints are no longer equal: a plain
  search costs 1 token, but a broker sweep costs 8, a username check 12 and an
  email check 3 — roughly one token per upstream request. The username cost is
  derived from the platform registry at import rather than hardcoded, so it
  cannot silently drift below the real fan-out. The default budget rose from 10
  to 30 to suit. Without this, one client could drain the upstream
  provider's quota in a couple of clicks and degrade the app for everyone.
- `is_safe_http_url` is now a `typing.TypeGuard[str]`, so a successful check
  narrows the value to `str` for type checkers instead of needing a second
  `isinstance` guard at every call site.
- All template rendering for the main page goes through one `_render_index`
  helper with the defaults in a single place; Jinja renders an undefined name as
  empty, so a route that forgot a variable used to fail silently.
- `utils` is a real package (`__init__.py`) rather than an implicit namespace
  package, which removes an ambiguous mypy module resolution.

### Fixed

- `.gitignore` ignored `data/*.json` with only two exceptions, so any newly
  added curated data file would have been silently missing from a fresh clone,
  leaving the app on its built-in fallbacks. Documented, and the new template
  file is now explicitly re-included.
- `send_petitions` routed every non-`duck_*` ID through `data/services.json`,
  which does not exist — so selecting a broker would have generated nothing at
  all. Broker IDs now resolve against the broker registry.
- Removed the unused `beautifulsoup4` dependency (nothing imported `bs4`), and
  declared `httpx`, which was previously used only transitively via `ddgs`.
- **A malformed HTTP 200 could be reported as "you are not exposed."** Both the
  Gravatar profile probe and the GitHub search treated a 200 response whose body
  was missing or the wrong shape as a confirmed absence. Absence is signalled by
  an explicit 404; an unparseable success body means the check did not really
  happen, and now resolves to `unknown`. This was the single worst failure mode
  available to this tool, and is now pinned by regression tests.
- **The username check undercharged the rate limiter by half**, costing 6 tokens
  while issuing 12 upstream requests. The cost is now derived from the platform
  registry, so it cannot drift again.
- **A blank name submitted to the broker deep check silently reused the previous
  scan's query**, sending an earlier name or email to 8 brokers without the user
  asking. A blank field is now rejected; only an entirely absent field reuses the
  last scan, which is the intended "scan, then deep check" flow.
- Exception objects are no longer interpolated into WARNING/ERROR logs on any
  probe path. Several `httpx` and `ddgs` exceptions stringify with the full
  request URL, which carries the name, email or username being searched; only the
  exception *type* is logged now, with full detail at DEBUG.
- The tracker's SQLite connections now use a lock timeout, so two browser tabs
  writing at once wait for each other instead of raising "database is locked".

### Security

- Every new `POST` route (`/check-brokers`, `/signals`, `/username`, and the
  three `/dashboard/*` routes) is covered by the existing CSRF protection, with
  a parametrised test asserting it for each.
- URLs taken from Gravatar profile data are attacker-influenced — any user can
  put arbitrary links in their own public profile — so they are validated before
  being rendered. An account whose URL fails validation is still disclosed to
  the user, but without a clickable link.
- Remote images are never embedded, only linked, so viewing a report does not
  announce the user's IP to a third party and the CSP stays unmodified.
- Usernames are character-restricted and URL-encoded before interpolation, so a
  handle containing `/`, `?`, `#` or a newline cannot alter the request target.
- Email addresses are never logged at INFO or above; failure logs carry only a
  static probe label and the exception type, because several httpx exceptions
  stringify with the full request URL.
- The tracker database is gitignored twice over (`instance/` and `*.sqlite3`)
  and is never transmitted anywhere.

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
