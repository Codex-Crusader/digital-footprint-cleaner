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
        "duck_1": "https://ok.example.com/profile",  # valid -> kept
    }
    petitions = petition_writer.send_petitions(["duck_0", "duck_1", "duck_2"], result_map)
    # Only duck_1 survives (duck_0 unsafe, duck_2 absent from map).
    assert len(petitions) == 1
    assert "https://ok.example.com/profile" in petitions[0]["text"]


def test_send_petitions_defaults_and_clamps_name():
    result_map = {"duck_0": "https://example.com"}
    long_name = "A" * 500
    petitions = petition_writer.send_petitions(["duck_0"], result_map, long_name)
    # Name is length-limited, so the full 500-char string never appears.
    assert long_name not in petitions[0]["text"]

    empty = petition_writer.send_petitions(["duck_0"], result_map, "")
    assert petition_writer.DEFAULT_NAME in empty[0]["text"]


# --- Customisable templates: legal basis + data types ------------------------


def test_available_options_are_non_empty_and_have_ids():
    bases = petition_writer.available_legal_bases()
    types_ = petition_writer.available_data_types()
    assert bases and types_
    assert all(b.get("id") and b.get("label") for b in bases)
    assert all(t.get("id") and t.get("phrase") for t in types_)


def test_build_petition_cites_selected_legal_basis():
    gdpr = petition_writer.build_petition(user_name="Jane Doe", legal_basis="gdpr")
    assert "Article 17" in gdpr
    assert "30 days" in gdpr

    ccpa = petition_writer.build_petition(user_name="Jane Doe", legal_basis="ccpa")
    assert "1798.105" in ccpa
    assert "45 days" in ccpa  # CCPA's deadline differs from GDPR's


def test_build_petition_unknown_legal_basis_falls_back_to_generic():
    text = petition_writer.build_petition(user_name="Jane", legal_basis="not-a-real-law")
    # Falls back rather than raising, so a stale form never costs a petition.
    assert "applicable data protection" in text
    assert "Jane" in text


def test_build_petition_renders_selected_data_types_as_prose():
    text = petition_writer.build_petition(
        user_name="Jane", data_types=["address", "phone", "relatives"]
    )
    assert "home addresses" in text
    assert "telephone number" in text
    # Three items are joined as "a, b and c".
    assert " and the names of my relatives" in text


def test_build_petition_ignores_unknown_data_types():
    # A tampered form must not be able to inject free text into the petition.
    text = petition_writer.build_petition(
        user_name="Jane", data_types=["address", "<script>alert(1)</script>", 42]
    )
    assert "<script>" not in text
    assert "42" not in text
    assert "home addresses" in text


def test_build_petition_defaults_to_whole_listing_when_nothing_selected():
    text = petition_writer.build_petition(user_name="Jane", data_types=[])
    assert "complete listing" in text


def test_build_petition_only_renders_safe_urls():
    safe = petition_writer.build_petition(
        user_name="Jane",
        url="https://broker.example/listing",
        opt_out_url="https://broker.example/optout",
    )
    assert "https://broker.example/listing" in safe
    assert "https://broker.example/optout" in safe

    unsafe = petition_writer.build_petition(
        user_name="Jane",
        url="javascript:alert(1)",
        opt_out_url="javascript:alert(2)",
    )
    assert "javascript:" not in unsafe


def test_send_petitions_uses_broker_lookup_for_name_and_opt_out():
    result_map = {"duck_0": "https://www.spokeo.com/Jane-Doe"}

    def fake_lookup(_url):
        return {"name": "Spokeo", "opt_out_url": "https://www.spokeo.com/optout"}

    petitions = petition_writer.send_petitions(
        ["duck_0"], result_map, "Jane Doe", broker_lookup=fake_lookup
    )
    assert petitions[0]["title"] == "Petition for Spokeo"
    assert "Spokeo" in petitions[0]["text"]
    assert "https://www.spokeo.com/optout" in petitions[0]["text"]


def test_send_petitions_survives_a_failing_broker_lookup():
    result_map = {"duck_0": "https://example.com/profile"}

    def exploding_lookup(_url):
        raise RuntimeError("registry unavailable")

    petitions = petition_writer.send_petitions(
        ["duck_0"], result_map, "Jane", broker_lookup=exploding_lookup
    )
    # Degrades to the generic wording instead of losing the petition.
    assert len(petitions) == 1
    assert "https://example.com/profile" in petitions[0]["text"]


def test_send_petitions_tolerates_non_dict_result_map():
    petitions = petition_writer.send_petitions(["duck_0"], "not-a-dict", "Jane")
    assert petitions == []


# --- broker_* IDs from the proactive opt-out checklist -----------------------


def _broker_registry(broker_id):
    registry = {
        "spokeo": {
            "id": "spokeo",
            "name": "Spokeo",
            "opt_out_url": "https://www.spokeo.com/optout",
        }
    }
    return registry.get(broker_id)


def test_send_petitions_resolves_broker_ids():
    # The checklist submits broker_<id>; without this path it silently
    # generated nothing, because data/services.json does not exist.
    petitions = petition_writer.send_petitions(
        ["broker_spokeo"], {}, "Jane Doe", broker_by_id=_broker_registry
    )
    assert len(petitions) == 1
    assert petitions[0]["title"] == "Petition for Spokeo"
    assert "https://www.spokeo.com/optout" in petitions[0]["text"]
    assert "Jane Doe" in petitions[0]["text"]


def test_send_petitions_skips_unknown_broker_ids():
    petitions = petition_writer.send_petitions(
        ["broker_nosuchsite"], {}, "Jane", broker_by_id=_broker_registry
    )
    assert petitions == []


def test_send_petitions_survives_failing_broker_by_id():
    def exploding(_broker_id):
        raise RuntimeError("registry unavailable")

    petitions = petition_writer.send_petitions(
        ["broker_spokeo"], {}, "Jane", broker_by_id=exploding
    )
    assert petitions == []  # skipped, but no exception escapes


def test_send_petitions_mixes_result_and_broker_selections():
    petitions = petition_writer.send_petitions(
        ["duck_0", "broker_spokeo"],
        {"duck_0": "https://example.com/profile"},
        "Jane Doe",
        data_types=["address"],
        legal_basis="gdpr",
        broker_by_id=_broker_registry,
    )
    assert len(petitions) == 2
    assert all("Article 17" in p["text"] for p in petitions)
    assert all("home addresses" in p["text"] for p in petitions)
