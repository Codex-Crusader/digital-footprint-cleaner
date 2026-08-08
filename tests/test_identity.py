"""Tests for the subject profile: name splitting, variants and factor matching."""

from datetime import date

# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

from utils.identity import IdentityProfile, normalise, split_name

TODAY = date(2026, 8, 8)


# --- name splitting ---------------------------------------------------------


def test_splits_simple_name():
    parts = split_name("Jane Doe")
    assert (parts.given, parts.middles, parts.family) == ("Jane", (), "Doe")


def test_splits_middle_names():
    parts = split_name("Jane Marie Elizabeth Doe")
    assert parts.given == "Jane"
    assert parts.middles == ("Marie", "Elizabeth")
    assert parts.family == "Doe"


def test_splits_directory_comma_form():
    parts = split_name("Doe, Jane Marie")
    assert (parts.given, parts.middles, parts.family) == ("Jane", ("Marie",), "Doe")


def test_particle_stays_with_the_family_name():
    # "van der Berg" is one surname. Splitting on whitespace would make "van" a
    # middle name and "Berg" the surname, so every surname check looks for the
    # wrong word.
    parts = split_name("Jane van der Berg")
    assert parts.family == "van der Berg"
    assert parts.middles == ()


def test_suffix_is_separated():
    parts = split_name("Robert Doe Jr.")
    assert parts.family == "Doe"
    assert parts.suffix == "Jr."


def test_single_token_is_treated_as_a_family_name():
    parts = split_name("Cher")
    assert parts.family == "Cher"
    assert not parts.is_full


def test_empty_name_is_handled():
    assert split_name("").family == ""
    assert split_name("   ").given == ""


# --- name variants ----------------------------------------------------------


def test_variants_include_directory_and_plain_forms():
    variants = IdentityProfile(full_name="Jane Marie Doe").name_variants()
    assert variants[0] == "Jane Marie Doe"  # as typed, first
    assert "Jane Doe" in variants
    assert "Doe, Jane" in variants
    assert "Jane M Doe" in variants


def test_comma_typed_name_still_searches_the_natural_spelling():
    # Regression: typing the directory form used to produce only that form, so
    # the spelling nearly every site actually uses was never searched.
    variants = IdentityProfile(full_name="Doe, Jane").name_variants()
    assert "Jane Doe" in variants


def test_variants_are_deduplicated():
    variants = IdentityProfile(full_name="Jane Doe").name_variants()
    assert len(variants) == len(set(variants))


def test_aliases_become_variants():
    profile = IdentityProfile(full_name="Jane Doe", aliases=("Jane Smith",))
    assert "Jane Smith" in profile.name_variants()


def test_core_name_drops_the_middle_name():
    assert IdentityProfile(full_name="Jane Marie Doe").core_name == "Jane Doe"
    assert IdentityProfile(full_name="Cher").core_name == "Cher"


# --- factor matching --------------------------------------------------------


def _matched(profile, text):
    return {f.key for f in profile.factors() if f.matches(text)}


def test_location_components_match_separately():
    profile = IdentityProfile(full_name="Jane Doe", location="Austin, TX")
    assert "location" in _matched(profile, "Lives in Austin these days")
    assert "location" in _matched(profile, "Somewhere, TX")


def test_word_boundaries_prevent_substring_false_positives():
    """A bare substring test manufactures matches out of unrelated words.

    "Ann" inside "announcement" and "40" inside "$400" would both otherwise
    read as corroboration, which for this tool means attributing a stranger's
    record to the user.
    """
    profile = IdentityProfile(full_name="Jane Doe", relatives=("Ann Doe",))
    assert _matched(profile, "Read the announcement from Doe Industries") == set()

    aged = IdentityProfile(full_name="Jane Doe", age="40", _today=TODAY)
    assert _matched(aged, "Priced at $400 for the weekend") == set()


def test_age_matches_stated_forms_and_birth_year():
    profile = IdentityProfile(full_name="Jane Doe", age="40", _today=TODAY)
    assert "age" in _matched(profile, "Jane Doe, Age 40, Austin")
    assert "age" in _matched(profile, "she is 40 years old")
    assert "age" in _matched(profile, "born in 1985")
    # 2026 - 40 gives either 1985 or 1986 without a birthday.
    assert "age" in _matched(profile, "b. 1986")


def test_implausible_age_is_ignored_rather_than_matched():
    profile = IdentityProfile(full_name="Jane Doe", age="999", _today=TODAY)
    assert not any(f.key == "age" for f in profile.factors())


def test_phone_matches_every_common_separator():
    profile = IdentityProfile(full_name="Jane Doe", phone="(555) 123-4567")
    for spelling in ("555-123-4567", "(555) 123-4567", "555.123.4567", "5551234567"):
        assert "phone" in _matched(profile, f"call {spelling} today"), spelling


def test_email_local_part_matches_a_redacted_address():
    profile = IdentityProfile(full_name="Jane Doe", email="jane.doe@example.com")
    assert "email" in _matched(profile, "contact jane.doe@...")


def test_accents_are_folded_for_comparison():
    assert normalise("Muñoz") == normalise("Munoz")


def test_name_is_not_itself_a_factor():
    # Every result matches the name by construction, so counting it would raise
    # every score equally and distinguish nothing.
    profile = IdentityProfile(full_name="Jane Doe", employer="Initech")
    assert {f.key for f in profile.factors()} == {"employer"}


# --- form parsing -----------------------------------------------------------


def test_from_form_clamps_and_splits_comma_lists():
    profile = IdentityProfile.from_form(
        {
            "user_info": "  Jane Doe  ",
            "location": "Austin, TX",
            "relatives": "Robert Doe, Mary Doe",
        }
    )
    assert profile.full_name == "Jane Doe"
    assert profile.relatives == ("Robert Doe", "Mary Doe")


def test_from_form_tolerates_a_completely_empty_submission():
    profile = IdentityProfile.from_form({})
    assert not profile.has_name
    assert profile.factors() == ()


@pytest.mark.parametrize("blank", ["", "   ", ",,,"])
def test_blank_list_fields_produce_no_entries(blank):
    assert IdentityProfile.from_form({"relatives": blank}).relatives == ()


def test_describe_lists_only_supplied_facts():
    profile = IdentityProfile(full_name="Jane Doe", employer="Initech")
    labels = {label for label, _ in profile.describe()}
    assert labels == {"Name", "Employer"}
