"""Shared input-validation and sanitisation helpers.

These are deliberately dependency-free (standard library only) so they can be
reused by the scanner, the petition writer and the Flask layer without pulling
in anything extra.
"""

from typing import TypeGuard
from urllib.parse import urlparse

# Only these URL schemes are ever considered safe to render in an ``href`` or to
# echo back into a generated petition. This blocks ``javascript:``, ``data:``,
# ``file:`` and similar vectors that can lead to XSS or local-file disclosure.
_ALLOWED_URL_SCHEMES = frozenset({"http", "https"})

# Hard upper bound on any user-supplied free-text field. Kept small because the
# only legitimate inputs are a name or an email address.
MAX_QUERY_LENGTH = 200
MAX_NAME_LENGTH = 100


def is_safe_http_url(url: object) -> TypeGuard[str]:
    """Return ``True`` only for well-formed ``http``/``https`` URLs.

    Accepts any object so callers never have to pre-validate the type; anything
    that is not a well-formed http/https string (other schemes, missing host,
    non-strings) is rejected.

    Declared as a :class:`~typing.TypeGuard` rather than a plain ``bool``: a
    successful check *is* proof the value is a ``str``, so type checkers narrow
    it automatically and callers do not need a second ``isinstance`` guard just
    to satisfy them.
    """
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return False
    return parsed.scheme in _ALLOWED_URL_SCHEMES and bool(parsed.netloc)


def clamp_text(value: object, max_length: int) -> str:
    """Strip surrounding whitespace and truncate ``value`` to ``max_length``.

    Accepts any object; non-string values are coerced to an empty string so
    callers never have to special-case ``None``.
    """
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]
