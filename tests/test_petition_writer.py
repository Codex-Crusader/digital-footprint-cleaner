from utils import petition_writer


def test_load_services_returns_empty_when_file_missing(monkeypatch):
    monkeypatch.setattr(petition_writer, "_SERVICES_PATH", "does-not-exist.json")
    assert petition_writer.load_services() == []


def test_send_petitions_generates_for_duck_ids():
    result_map = {"duck_0": "https://example.com/profile"}
    petitions = petition_writer.send_petitions(["duck_0"], result_map, "Jane Doe")
    assert len(petitions) == 1
    assert "https://example.com/profile" in petitions[0]["text"]
    assert "Jane Doe" in petitions[0]["text"]


def test_send_petitions_skips_unsafe_or_missing_urls():
    result_map = {
        "duck_0": "javascript:alert(1)",  # unsafe scheme -> skipped
        "duck_1": "https://ok.example.com",  # valid -> kept
    }
    petitions = petition_writer.send_petitions(["duck_0", "duck_1", "duck_2"], result_map)
    # Only duck_1 survives (duck_0 unsafe, duck_2 absent from map).
    assert len(petitions) == 1
    assert "ok.example.com" in petitions[0]["text"]


def test_send_petitions_defaults_and_clamps_name():
    result_map = {"duck_0": "https://example.com"}
    long_name = "A" * 500
    petitions = petition_writer.send_petitions(["duck_0"], result_map, long_name)
    # Name is length-limited, so the full 500-char string never appears.
    assert long_name not in petitions[0]["text"]

    empty = petition_writer.send_petitions(["duck_0"], result_map, "")
    assert petition_writer.DEFAULT_NAME in empty[0]["text"]
