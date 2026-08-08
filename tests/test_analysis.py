from datetime import date

import analysis
from utils.identity import IdentityProfile


def _sample_results():
    return [
        {"id": "duck_0", "title": "Spokeo",
         "url": "https://www.spokeo.com/Jane-Doe", "snippet": ""},
        {"id": "duck_1", "title": "LinkedIn",
         "url": "https://www.linkedin.com/in/jane", "snippet": ""},
        {"id": "duck_2", "title": "Wikipedia",
         "url": "https://en.wikipedia.org/wiki/Jane", "snippet": ""},
        {"id": "duck_3", "title": "Radaris",
         "url": "https://radaris.com/p/Jane", "snippet": ""},
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


# --- Match confidence -------------------------------------------------------
# Whether a result is *this* person or a namesake. A privacy tool that presents
# a stranger's records as the user's invites removal requests over someone
# else's data and inflates an exposure score with records that were never
# theirs, so these are the sharpest assertions in the suite.

def _profile(**kwargs):
    kwargs.setdefault("full_name", "Jane Doe")
    kwargs.setdefault("_today", date(2026, 8, 8))
    return IdentityProfile(**kwargs)


def _result(url, title="Result", snippet=""):
    return {"id": "deep_0", "title": title, "url": url, "snippet": snippet}


def test_no_profile_leaves_every_result_possible():
    # The tool must stay fully usable for someone who supplies nothing but a
    # name, so scoring degrades to a single neutral band rather than refusing.
    confidence, matched = analysis.score_match(_result("https://example.com"), None)
    assert confidence == analysis.CONFIDENCE_POSSIBLE
    assert matched == []


def test_two_corroborating_facts_reach_strong():
    confidence, matched = analysis.score_match(
        _result("https://linkedin.com/in/janedoe",
                snippet="Jane Doe - Initech - Austin, Texas"),
        _profile(location="Austin", employer="Initech"),
    )
    assert confidence == analysis.CONFIDENCE_STRONG
    assert {m["key"] for m in matched} == {"location", "employer"}


def test_one_fact_reaches_likely():
    confidence, _ = analysis.score_match(
        _result("https://example.com/x", snippet="Jane Doe of Austin"),
        _profile(location="Austin"),
    )
    assert confidence == analysis.CONFIDENCE_LIKELY


def test_namesake_without_corroboration_stays_possible():
    confidence, matched = analysis.score_match(
        _result("https://www.spokeo.com/Jane-Doe/Ohio",
                snippet="Jane Doe, age 71, Akron OH"),
        _profile(location="Austin", employer="Initech"),
    )
    assert confidence == analysis.CONFIDENCE_POSSIBLE
    assert matched == []


def test_page_without_the_name_is_unverified_however_many_facts_match():
    """Name presence is a floor, not a bonus.

    A company's own page matches the employer and the city while the person is
    entirely absent from it. Without this rule it would score higher than the
    user's actual profile page.
    """
    confidence, matched = analysis.score_match(
        _result("https://initech.com/austin",
                title="Initech Austin office",
                snippet="Our Austin, TX office. Founded 1985."),
        _profile(location="Austin, TX", employer="Initech", age="40"),
    )
    assert confidence == analysis.CONFIDENCE_UNVERIFIED
    assert matched == []


def test_facts_are_matched_from_the_url_path_too():
    # Identifying details are often only in the path: /Jane-Doe/TX/Austin names
    # a city that appears in neither the title nor the snippet.
    confidence, matched = analysis.score_match(
        _result("https://radaris.com/p/Jane/Doe/Austin-TX/"),
        _profile(location="Austin"),
    )
    assert confidence == analysis.CONFIDENCE_LIKELY
    assert [m["key"] for m in matched] == ["location"]


def test_name_matches_across_a_middle_initial():
    confidence, _ = analysis.score_match(
        _result("https://example.com", snippet="Jane M. Doe lives in Austin"),
        _profile(location="Austin"),
    )
    assert confidence != analysis.CONFIDENCE_UNVERIFIED


def test_name_matches_the_directory_comma_form():
    confidence, _ = analysis.score_match(
        _result("https://example.com", snippet="Doe, Jane - record 12"),
        _profile(),
    )
    assert confidence != analysis.CONFIDENCE_UNVERIFIED


# --- analyze() with a profile ----------------------------------------------


def test_analyze_without_a_profile_is_unchanged():
    # Backwards compatibility: the no-profile path must score exactly as before.
    assert analysis.analyze(_sample_results())["score"] == analysis.analyze(
        _sample_results(), profile=None
    )["score"]


def test_unverified_results_are_split_out_not_deleted():
    results = [
        _result("https://example.com/jane", snippet="Jane Doe of Austin"),
        {"id": "deep_1", "title": "Unrelated", "url": "https://example.com/other",
         "snippet": "A page about someone else entirely"},
    ]
    report = analysis.analyze(results, profile=_profile(location="Austin"))
    assert report["total"] == 2
    assert len(report["unverified"]) == 1
    assert all(
        r["confidence"] != analysis.CONFIDENCE_UNVERIFIED
        for cat in report["categories"] for r in cat["results"]
    )


def test_unverified_results_do_not_inflate_the_exposure_score():
    matching = [_result("https://www.spokeo.com/Jane-Doe", snippet="Jane Doe, Austin")]
    padded = matching + [
        {"id": f"deep_{i}", "title": "Other", "url": f"https://www.radaris.com/p{i}",
         "snippet": "a completely different person"}
        for i in range(1, 5)
    ]
    profile = _profile(location="Austin")
    assert (
        analysis.analyze(padded, profile=profile)["score"]
        == analysis.analyze(matching, profile=profile)["score"]
    )


def test_results_are_ordered_best_match_first():
    results = [
        {"id": "deep_0", "title": "Namesake", "url": "https://www.spokeo.com/a",
         "snippet": "Jane Doe, Akron OH"},
        {"id": "deep_1", "title": "Right one", "url": "https://www.spokeo.com/b",
         "snippet": "Jane Doe, Austin, works at Initech"},
    ]
    report = analysis.analyze(results, profile=_profile(location="Austin", employer="Initech"))
    broker_cat = next(c for c in report["categories"] if c["key"] == "data_broker")
    assert broker_cat["results"][0]["id"] == "deep_1"


def test_confidence_counts_are_reported():
    report = analysis.analyze(
        [_result("https://example.com", snippet="Jane Doe of Austin")],
        profile=_profile(location="Austin"),
    )
    assert report["confidence_counts"][analysis.CONFIDENCE_LIKELY] == 1
    assert report["profiled"] is True


def test_profiled_is_false_when_only_a_name_was_given():
    report = analysis.analyze([_result("https://example.com")], profile=_profile())
    assert report["profiled"] is False
