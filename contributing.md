# Contributing to Digital Footprint Cleaner

Thanks for your interest in contributing. Your help is appreciated in making
this privacy-focused tool better, smarter, and more useful.

## Project Goal

Digital Footprint Cleaner is an open-source web app built in Python and HTML
that helps people find where their personal data is exposed online and generate
removal requests. The project aims to be simple, secure, and honest about what
it can and cannot do.

## Getting Started

- Fork this repository.
- Clone your fork:

  ```bash
  git clone https://github.com/Codex-Crusader/digital-footprint-cleaner.git
  cd digital-footprint-cleaner
  ```

- Create a virtual environment and activate it.
- Install dependencies:

  ```bash
  pip install -r requirements-dev.txt
  ```

- Run the app locally:

  ```bash
  python app.py
  ```

## What You Can Work On

- Improve search relevance or result classification (`analysis.py`).
- Add or verify data-broker opt-out entries in `data/brokers.json`.
- Enhance the removal petition templates.
- Improve frontend design or accessibility.
- Add unit or integration tests.
- Refactor to reduce complexity or improve modularity.

## Code Style

- Follow PEP 8 for Python code.
- Keep functions short, reusable, and documented.
- Avoid hardcoding URLs or secrets; read configuration from the environment.
- Use English for all comments and documentation.

## Testing

Run the test suite before submitting a pull request:

```bash
pip install -r requirements-dev.txt
pytest
```

Make sure the suite passes and the app still runs (`python app.py`, then visit
`http://127.0.0.1:5000`).

## Submitting a Pull Request

1. Create a new branch:

   ```bash
   git checkout -b your-feature-name
   ```

2. Commit your changes with a clear message:

   ```bash
   git commit -m "Add: verified opt-out entry for XYZ broker"
   ```

3. Push to your fork and open a pull request:

   ```bash
   git push origin your-feature-name
   ```

4. In your PR, describe what the change does and why it is needed.

## Ask First

If you are unsure whether your idea fits the scope of the project, open an
[issue](https://github.com/Codex-Crusader/digital-footprint-cleaner/issues) to
discuss it before starting.

## Code of Conduct

Be kind, respectful, and helpful. Harassment or discrimination of any kind will
not be tolerated. We aim to maintain a safe, inclusive, and collaborative space
for all contributors.
