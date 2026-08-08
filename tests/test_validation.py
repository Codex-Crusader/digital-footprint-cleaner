from utils.validation import clamp_text, is_safe_http_url


# The plain-http literals below are the subject under test, not links to follow:
# `is_safe_http_url` must accept `http` as well as `https`, and must reject a
# host-less `http://`. Rewriting them to https would delete that coverage.
# noinspection HttpUrlsUsage
def test_is_safe_url_accepts_http_and_https():
    assert is_safe_http_url("http://example.com/page")
    assert is_safe_http_url("https://example.com")


def test_is_safe_url_rejects_dangerous_schemes():
    assert not is_safe_http_url("javascript:alert(1)")
    assert not is_safe_http_url("data:text/html,<script>1</script>")
    assert not is_safe_http_url("file:///etc/passwd")


# noinspection HttpUrlsUsage
def test_is_safe_url_rejects_missing_host():
    assert not is_safe_http_url("http://")
    assert not is_safe_http_url("https:///nohost")


def test_is_safe_url_rejects_non_strings_and_empty():
    assert not is_safe_http_url("")
    assert not is_safe_http_url(None)
    assert not is_safe_http_url(123)


def test_clamp_text_strips_and_truncates():
    assert clamp_text("  hello  ", 100) == "hello"
    assert clamp_text("abcdef", 3) == "abc"


def test_clamp_text_coerces_non_strings_to_empty():
    assert clamp_text(None, 10) == ""
    assert clamp_text(42, 10) == ""
