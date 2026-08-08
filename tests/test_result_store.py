"""Tests for the server-side result map.

The store exists because the old session-cookie approach failed silently once
scans grew past ten results, so several of these assert the *failure* shape:
an expired or unknown token must degrade to "run the search again", never to a
partial map or an exception.
"""

from utils.result_store import ResultStore


def _mapping(count):
    return {f"deep_{i}": f"https://example.com/{i}" for i in range(count)}


def test_round_trips_a_mapping():
    store = ResultStore()
    token = store.put({"deep_0": "https://example.com/a"})
    assert store.get(token) == {"deep_0": "https://example.com/a"}


def test_holds_far_more_than_a_session_cookie_could():
    # The motivating bug: ~100 URLs overflow a 4KB signed cookie, and the
    # browser drops it without telling anyone.
    store = ResultStore()
    token = store.put(_mapping(120))
    assert len(store.get(token)) == 120


def test_reusing_a_token_replaces_rather_than_accumulates():
    # Otherwise every re-scan in one session retains another full map.
    store = ResultStore()
    first = store.put({"deep_0": "https://example.com/a"})
    second = store.put({"deep_1": "https://example.com/b"}, token=first)
    assert second == first
    assert store.get(first) == {"deep_1": "https://example.com/b"}
    assert len(store) == 1


def test_unknown_token_returns_an_empty_map():
    assert ResultStore().get("nope") == {}


def test_malformed_tokens_are_handled_like_unknown_ones():
    store = ResultStore()
    for bad in (None, "", 12, object(), b"bytes"):
        assert store.get(bad) == {}


def test_expired_entry_is_dropped():
    store = ResultStore(ttl_seconds=-1)  # already expired on arrival
    token = store.put({"deep_0": "https://example.com/a"})
    assert store.get(token) == {}


def test_expired_entries_do_not_linger_in_memory():
    store = ResultStore(ttl_seconds=-1)
    store.put({"deep_0": "https://example.com/a"})
    store.put({"deep_1": "https://example.com/b"})
    assert len(store) <= 1


def test_session_count_is_capped():
    # Without a cap, a crawler hitting the search endpoint grows this map
    # without limit -- a slow memory-exhaustion bug.
    store = ResultStore(max_sessions=3)
    for _ in range(10):
        store.put({"deep_0": "https://example.com/a"})
    assert len(store) <= 3


def test_oldest_sessions_are_evicted_first():
    store = ResultStore(max_sessions=2)
    oldest = store.put({"deep_0": "https://example.com/old"})
    store.put({"deep_0": "https://example.com/mid"})
    store.put({"deep_0": "https://example.com/new"})
    assert store.get(oldest) == {}


def test_entries_per_scan_are_capped():
    store = ResultStore(max_entries=5)
    token = store.put(_mapping(50))
    assert len(store.get(token)) == 5


def test_drop_forgets_one_scan():
    store = ResultStore()
    token = store.put({"deep_0": "https://example.com/a"})
    store.drop(token)
    assert store.get(token) == {}


def test_clear_forgets_everything():
    store = ResultStore()
    store.put({"deep_0": "https://example.com/a"})
    store.clear()
    assert len(store) == 0


def test_returned_map_is_a_copy():
    # A caller mutating its result must not corrupt what the next request sees.
    store = ResultStore()
    token = store.put({"deep_0": "https://example.com/a"})
    store.get(token)["deep_0"] = "https://evil.example"
    assert store.get(token) == {"deep_0": "https://example.com/a"}


def test_keys_and_values_are_coerced_to_strings():
    store = ResultStore()
    token = store.put({1: 2})
    assert store.get(token) == {"1": "2"}
