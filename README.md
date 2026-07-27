# Digital Footprint Cleaner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE_MIT.md)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Tests](https://img.shields.io/badge/tests-44%20passing-brightgreen.svg)](tests/)
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
- **Broker "Check" links.** After a scan, each broker gets a name-scoped search link so you can confirm whether that site actually lists you.
- **Auto-generate removal petitions** in a GDPR/IT-Act-style format, shown on screen ready to copy.
- **Legal guide** to inform you of your rights.
- **Security-hardened** by default (CSRF protection, strict CSP, hardened cookies, rate limiting). See [Security](#security).
- Clean, card-based UI.
- Written entirely in Python and HTML, no paid services required.

### How it works, and its honest limits

A plain web search surfaces mentions of you, but the real privacy exposure is
the data-broker / people-search sites that aggregate your address, phone, age,
and relatives. This tool:

1. Runs a privacy-respecting web search and classifies every result.
2. Flags any data-broker listing that appears in results and links its opt-out page.
3. Always shows a proactive opt-out checklist for the major brokers, with per-broker "Check" links.

Honest limitation: general web search does not reliably rank data-broker
listing pages, so the automatic "detected on broker X" step often finds nothing
even when you are listed. That is why the proactive checklist is the primary
feature. Use the "Check" link to run a scoped search on each broker, then opt
out. Broker removals are also not permanent (data typically reappears in 3 to 6
months), so repeat periodically. This tool is for checking your own footprint,
or someone's with their consent, not for looking up third parties.

## Tech Stack

- **Frontend**: HTML (Jinja2 templates) and a static stylesheet.
- **Backend**: Python (Flask).
- **Search**: [`ddgs`](https://pypi.org/project/ddgs/), a free, privacy-respecting DuckDuckGo client.
- **Analysis**: custom result classification, broker detection, and risk scoring.
- **Tests**: `pytest`.

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
| `SEARCH_RATE_LIMIT` | `10` | Max searches per IP within the window. |
| `SEARCH_RATE_WINDOW` | `60` | Rate-limit window in seconds. |

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
risk scoring, broker detection, petition generation, the (mocked) search
backend, and the security controls (CSRF, headers, rate limiting).

## Project Structure

```
digital-footprint-cleaner/
├── app.py                  # Flask app + security controls (CSRF, headers, rate limiting)
├── scanner.py              # DuckDuckGo search + result sanitisation
├── analysis.py             # Result classification, broker detection, risk scoring
├── requirements.txt        # Runtime dependencies
├── requirements-dev.txt    # Test dependencies
├── pytest.ini              # Test configuration
├── .env.example            # Documented configuration template
├── SECURITY.md             # Security policy & protections
├── utils/
│   ├── petition_writer.py  # Petition generation
│   └── validation.py       # Shared input/URL validation helpers
├── templates/
│   ├── index.html
│   └── legal.html
├── static/
│   └── css/style.css       # All styling (kept external for a strict CSP)
├── tests/                  # pytest suite
├── data/
│   └── brokers.json        # Curated, verified data-broker opt-out registry
├── LICENSE_MIT.md
├── README.md
└── .gitignore
```

## Roadmap

- Email signals (Gravatar avatar lookup, GitHub accounts by email).
- Username presence check across platforms.
- Optional breach checking (requires an API key from a provider such as Have I Been Pwned).
- Customizable petition templates based on site and data type.
- A privacy dashboard to track removal requests and their status.

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
