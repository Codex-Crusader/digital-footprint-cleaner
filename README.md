# Digital Footprint Cleaner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE_MIT.md)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-192%20passing-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/security-hardened-6a0dad.svg)](SECURITY.md)

A privacy-first, open-source web app that helps you find where your personal
information is exposed online and generate ready-to-send data-removal requests.

## Screenshots

**Home** - enter a name or email, with the proactive data-broker opt-out checklist always available:

![Home page](docs/screenshots/home.jpg)

**Exposure report** — results are classified by category and scored by risk:

![Exposure report](docs/screenshots/exposure-report.jpg)

**Data-broker checklist** - verified opt-out links plus a per-broker "Check" to confirm whether a site lists you:

![Data-broker opt-out checklist](docs/screenshots/broker-checklist.jpg)

## Features

- **Search** for your name or email using DuckDuckGo (privacy-respecting, no tracking).
- **Exposure report.** Results are classified (data brokers, social media, professional, public records, news) and given an overall risk score driven by data-broker presence.
- **Data-broker opt-out checklist.** Direct, verified opt-out links for 30+ major US people-search sites (Spokeo, Whitepages, BeenVerified, Radaris). This is the most useful privacy action and the tool's core value.
- **Data-broker deep check.** Runs a site-scoped search against each broker individually, finding listing pages that a general web search does not rank. This is the direct fix for the tool's oldest limitation.
- **Email signals.** Shows what an email address alone gives away: a public Gravatar profile can expose your real name, location, employer and linked social accounts, plus any GitHub account registered to that address.
- **Username presence check.** Looks for public profile pages using the same handle across 17 platforms, and is explicit about which ones cannot be checked reliably instead of guessing.
- **Customisable removal petitions.** Choose the legal basis (GDPR, CCPA/CPRA, India's DPDP Act, or a neutral request) and exactly which data to demand erasure of (address, phone, relatives, employment, ...). Each petition cites the right statute and deadline.
- **Removal tracker.** A local dashboard recording who you wrote to, what they said, and what still needs chasing. Brokers re-list people after three to six months, so this is where the long game is won.
- **Legal guide** to inform you of your rights.
- **Security-hardened** by default (CSRF protection, strict CSP, hardened cookies, cost-weighted rate limiting). See [Security](#security).
- Clean, card-based UI.
- Written entirely in Python and HTML, no paid services required.

### Honest by design: three states, not two

Every check reports **found**, **not found**, or **unknown** — and the UI colours
them differently. "Unknown" means the check was blocked, throttled or timed out.

This distinction is the whole point. Telling someone they are absent from a data
broker when the check merely failed is the most damaging thing a privacy tool can
get wrong, and it is what most username-checker style tools do. Platforms that
answer unreliably (Instagram, X, TikTok, Twitch, Tumblr all return "200 OK" for
every handle) are not requested at all, rather than guessed at.

### How it works, and its honest limits

A plain web search surfaces mentions of you, but the real privacy exposure is
the data-broker / people-search sites that aggregate your address, phone, age,
and relatives. This tool:

1. Runs a privacy-respecting web search and classifies every result.
2. Flags any data-broker listing that appears in results and links its opt-out page.
3. Runs a **deep check** — one site-scoped search per broker — to find listings the
   broad scan misses.
4. Always shows a proactive opt-out checklist for the major brokers.
5. Generates a petition citing the law that applies to you, and tracks it to completion.

**What got better.** A general web search does not reliably rank data-broker
listing pages, so the automatic "detected on broker X" step used to find nothing
even when you were listed. The deep check attacks that directly by querying each
broker's domain individually.

**What is still true.** The deep check is bounded: it covers the first 8 brokers
within a 25-second budget, because the search backend throttles aggressively.
Brokers beyond that are reported as `skipped`, not as "clean". Results are cached
for 15 minutes. Broker removals are also not permanent — data typically reappears
in 3 to 6 months — which is exactly what the removal tracker is for.

**Email and username checks have limits too.** GitHub only finds accounts whose
owner made their email public, and without a `GITHUB_TOKEN` that probe is
rate-limited to ~10 requests per minute for the whole process, so it will often
report `unknown`. A username match means a profile page exists at that address —
not that it belongs to you.

This tool is for checking your own footprint, or someone's with their consent,
not for looking up third parties. It takes one name or one username at a time and
deliberately implements no bulk or CSV input.

## Your data

- **Nothing is sent to us.** There is no backend service; the app talks only to
  the sites being checked (DuckDuckGo, Gravatar, GitHub, and the platforms in the
  username check).
- **The removal tracker stores data locally** in `instance/tracker.sqlite3`
  (gitignored, override with `DFC_DB_PATH`). It records site names, statuses and
  your own notes — never search results or scan output.
- **Delete everything at any time** with the "Delete All Tracked Requests" button
  on the dashboard.
- Remote images are never loaded. A Gravatar avatar is reported as existing and
  linked, not embedded, so viewing a report does not announce your IP to a third
  party.

## Tech Stack

- **Frontend**: HTML (Jinja2 templates) and a static stylesheet. No JavaScript, which is what lets the Content Security Policy stay this strict.
- **Backend**: Python (Flask).
- **Search**: [`ddgs`](https://pypi.org/project/ddgs/), a free, privacy-respecting DuckDuckGo client.
- **HTTP probes**: [`httpx`](https://www.python-httpx.org/), with per-request timeouts and a bounded thread pool.
- **Storage**: SQLite (standard library) for the local removal tracker. No database server to run.
- **Analysis**: custom result classification, broker detection, and risk scoring.
- **Tests**: `pytest`; `mypy`, `pyflakes` and `pycodestyle` for static analysis.

> Note: this project uses the maintained `ddgs` package. The older
> `duckduckgo-search` package is deprecated and no longer returns results, so it
> has been replaced.

## Installation

1. Clone the repo:

   ```bash
   git clone https://github.com/Codex-Crusader/digital-footprint-cleaner.git
   cd digital-footprint-cleaner
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate        # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the app:

   ```bash
   python app.py
   ```

5. Open `http://127.0.0.1:5000` in your browser.

## Configuration

All configuration is read from environment variables. Copy `.env.example` to
`.env` for reference, then export the values in your shell (the app does not
auto-load `.env`).

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | random, ephemeral | Signs session cookies. Set a strong value in production. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `FLASK_ENV` | `production` | Set to `development` to enable debug mode locally. Never use `development` in production. |
| `SESSION_COOKIE_SECURE` | `false` | Set to `true` to send session cookies only over HTTPS. |
| `SEARCH_RATE_LIMIT` | `30` | Rate-limit budget per IP within the window, counted in **tokens**, not requests. A plain search costs 1; a broker deep check costs 8, a username check 12, an email check 3 — roughly one token per upstream request they make. |
| `SEARCH_RATE_WINDOW` | `60` | Rate-limit window in seconds. |
| `GITHUB_TOKEN` | unset | Optional. Raises the GitHub search rate limit for the email-signals check. A token with **no scopes** is sufficient. Without it that probe usually reports `unknown`. |
| `DFC_DB_PATH` | `instance/tracker.sqlite3` | Where the removal tracker stores its local SQLite database. |

## Security

Security controls are applied by default and centralised in `app.py` for easy auditing:

- CSRF protection on every `POST` (per-session token, constant-time comparison).
- Content Security Policy with no inline scripts or styles and no third-party origins.
- Anti-clickjacking (`X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`).
- Hardened session cookies (`HttpOnly`, `SameSite=Lax`, optional `Secure`).
- URL validation: only `http`/`https` result links are rendered, blocking `javascript:` and `data:` injection.
- Request-size limit and per-IP rate limiting on search.

See [SECURITY.md](SECURITY.md) for the full list and deployment guidance.

## Testing

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers input validation, URL sanitisation, result classification and
risk scoring, broker detection, the broker deep check, email signals, username
presence checks, petition generation, the removal tracker, the (mocked) search
backend, and the security controls (CSRF, headers, rate limiting).

**No test touches the network.** Every outbound call is behind an injected HTTP
client or a monkeypatched backend, so the suite is fast, deterministic and
offline. `pytest.ini` sets `filterwarnings = error`, so any new warning fails the
build.

Static analysis — all four must be clean before a PR:

```bash
pytest                                                   # 192 tests
mypy                                                     # config in pyproject.toml
pycodestyle app.py scanner.py analysis.py utils tests    # config in setup.cfg
pyflakes  app.py scanner.py analysis.py utils tests
```

## Project Structure

```
digital-footprint-cleaner/
├── app.py                  # Flask app + security controls (CSRF, headers, rate limiting)
├── scanner.py              # DuckDuckGo search, result sanitisation, broker deep check
├── analysis.py             # Result classification, broker detection, risk scoring
├── pyproject.toml          # Project metadata, dependency list, mypy config
├── setup.cfg               # pycodestyle config (it cannot read pyproject.toml)
├── requirements.txt        # Runtime dependencies (mirrors pyproject.toml)
├── requirements-dev.txt    # Test dependencies
├── pytest.ini              # Test configuration
├── .env.example            # Documented configuration template
├── SECURITY.md             # Security policy & protections
├── utils/
│   ├── validation.py       # Shared input/URL validation helpers
│   ├── http_client.py      # Structural type for the injectable HTTP client
│   ├── petition_writer.py  # Petition generation from legal basis + data types
│   ├── email_signals.py    # Gravatar profile + GitHub-by-email probes
│   ├── username_check.py   # Cross-platform username presence checks
│   └── tracker.py          # Local SQLite store for removal requests
├── templates/
│   ├── index.html          # Scan, probes, results, petitions
│   ├── dashboard.html      # Removal-request tracker
│   └── legal.html
├── static/
│   └── css/style.css       # All styling (kept external for a strict CSP)
├── tests/                  # pytest suite (192 tests)
├── data/
│   ├── brokers.json        # Curated, verified data-broker opt-out registry
│   └── petition_templates.json  # Legal bases, data types, petition body
├── instance/               # Local tracker database (gitignored, created on demand)
├── LICENSE_MIT.md
├── README.md
└── .gitignore
```

> Note on `data/`: `.gitignore` ignores `data/*.json` and re-includes each
> curated file explicitly. If you add a data file, add an `!data/yourfile.json`
> exception too, or it will be missing from a fresh clone and the app will
> silently fall back to its built-in defaults.

## Roadmap

Shipped since 1.0: email signals, username presence checks, customisable
petition templates, the removal-request dashboard, and the broker deep check.

Still open:

- Optional breach checking (requires an API key from a provider such as Have I Been Pwned).
- Scheduled re-checks, so re-listed broker data is caught automatically rather than
  relying on the user to remember.
- Export the tracker to CSV/JSON for people who want their records outside the app.
- Broaden the broker registry beyond US people-search sites (EU and India equivalents).

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](contributing.md) for guidelines.

You can suggest features, improve petition logic, add broker entries or legal
templates, refine search filters, or improve documentation.

Fork it, improve it, submit a PR.

## License

This project is licensed under the [MIT License](LICENSE_MIT.md).

## Acknowledgements

- [DuckDuckGo](https://duckduckgo.com) for privacy-friendly web search.
- [Flask](https://flask.palletsprojects.com) for its lightweight Python web framework.
- The maintained [Big-Ass Data Broker Opt-Out List](https://github.com/yaelwrites/Big-Ass-Data-Broker-Opt-Out-List) for verified opt-out references.
