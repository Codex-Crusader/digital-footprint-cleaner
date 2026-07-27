import analysis


def _sample_results():
    return [
        {"id": "duck_0", "title": "Spokeo", "url": "https://www.spokeo.com/Jane-Doe", "snippet": ""},
        {"id": "duck_1", "title": "LinkedIn", "url": "https://www.linkedin.com/in/jane", "snippet": ""},
        {"id": "duck_2", "title": "Wikipedia", "url": "https://en.wikipedia.org/wiki/Jane", "snippet": ""},
        {"id": "duck_3", "title": "Radaris", "url": "https://radaris.com/p/Jane", "snippet": ""},
    ]


def test_classify_data_broker_domains():
    assert analysis.classify("https://www.spokeo.com/John-Doe") == "data_broker"
    assert analysis.classify("https://radaris.com/p/John/Doe") == "data_broker"


def test_classify_social_professional_reference():
    assert analysis.classify("https://www.linkedin.com/in/jane") == "professional"
    assert analysis.classify("https://github.com/jane") == "professional"
    assert analysis.classify("https://www.facebook.com/jane") == "social_media"
    assert analysis.classify("https://en.wikipedia.org/wiki/Jane") == "reference"
    assert analysis.classify("https://www.reddit.com/u/jane") == "forum"


def test_classify_gov_is_public_records():
    assert analysis.classify("https://sos.state.tx.gov/records") == "public_records"


def test_classify_unknown_is_other():
    assert analysis.classify("https://some-random-blog.example/jane") == "other"


def test_classify_subdomain_matches_broker():
    assert analysis.classify("https://profile.spokeo.com/x") == "data_broker"


def test_classify_dot_us_is_not_public_records():
    assert analysis.classify("https://mybusiness.us/about") == "other"


def test_broker_for_returns_registry_entry_with_opt_out():
    broker = analysis.broker_for("https://www.whitepages.com/name/Jane-Doe")
    assert broker is not None
    assert broker["name"] == "Whitepages"
    assert broker["opt_out_url"].startswith("https://")


def test_broker_for_non_broker_returns_none():
    assert analysis.broker_for("https://example.com") is None


def test_analyze_detects_brokers_found():
    report = analysis.analyze(_sample_results())
    names = {b["name"] for b in report["brokers_found"]}
    assert names == {"Spokeo", "Radaris"}


def test_analyze_categories_sorted_by_risk():
    report = analysis.analyze(_sample_results())
    keys = [c["key"] for c in report["categories"]]
    # data_broker (weight 20) must come before professional/reference.
    assert keys[0] == "data_broker"


def test_analyze_risk_level_high_with_multiple_brokers():
    report = analysis.analyze(_sample_results())
    # 2 brokers (20 each) + others -> well above the High threshold.
    assert report["risk_level"] == "High"
    assert report["score"] > 0


def test_analyze_volume_of_benign_mentions_does_not_read_high():
    # 10 social-media hits, zero brokers: high volume but not a broker
    # exposure -> must not be "High".
    many_social = [
        {"id": f"duck_{i}", "title": "x", "url": f"https://facebook.com/p{i}", "snippet": ""}
        for i in range(10)
    ]
    report = analysis.analyze(many_social)
    assert report["brokers_found"] == []
    assert report["risk_level"] != "High"


def test_analyze_single_broker_is_at_least_medium():
    one_broker = [
        {"id": "duck_0", "title": "S", "url": "https://www.spokeo.com/a", "snippet": ""}
    ]
    report = analysis.analyze(one_broker)
    assert report["risk_level"] in ("Medium", "High")


def test_analyze_empty_results_is_low_risk():
    report = analysis.analyze([])
    assert report["total"] == 0
    assert report["risk_level"] == "Low"
    assert report["brokers_found"] == []


def test_analyze_no_duplicate_brokers():
    dupes = [
        {"id": "duck_0", "title": "S1", "url": "https://www.spokeo.com/a", "snippet": ""},
        {"id": "duck_1", "title": "S2", "url": "https://www.spokeo.com/b", "snippet": ""},
    ]
    report = analysis.analyze(dupes)
    assert len(report["brokers_found"]) == 1


def test_registry_all_brokers_loaded_with_https_opt_out():
    brokers = analysis.all_brokers()
    assert len(brokers) >= 20
    for broker in brokers:
        assert broker["opt_out_url"].startswith("https://")
        assert broker["domain"] and "." in broker["domain"]
