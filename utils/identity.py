"""The subject of a search, and the facts used to tell them apart from namesakes.

A name on its own is a bad identifier. "James Smith" matches tens of thousands
of people, and a search for it returns a pile of results belonging to strangers.
The fix is not a longer query, see below, it is collecting a handful of
*corroborating facts* and using them to judge which results actually belong to
the person being searched for.

:class:`IdentityProfile` holds those facts. It does two jobs:

* :meth:`IdentityProfile.name_variants` produces the small set of name spellings
  worth searching for (``"Jane Doe"``, ``"Doe, Jane"``, ``"Jane M Doe"``, ...).
  Broker listings and directories are inconsistent about name order and middle
  names, so one spelling misses listings that plainly exist.
* :meth:`IdentityProfile.factors` produces matchable :class:`Factor` objects:
  employer, city, school, phone, birth year, relatives: that
  :mod:`analysis` scores each result against.

**Why factors are never appended to the query.** It is tempting to search
``"Jane Doe" Austin Initech "Staff Engineer" 1985``. That query returns nothing.
Every extra term is an AND against a full-text index, so recall collapses long
before precision improves, and the deep scan ends up finding *less* than a plain
name search. Factors are therefore a *ranking* input, not a *retrieval* one:
queries stay short and high-recall, and the factors sort and filter what comes
back. The one exception is location, which genuinely helps retrieval and is
handled explicitly by the query planner.

Everything here is pure and standard-library only, so it is fully unit-testable
without network access.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date
from typing import Iterable, Mapping

from utils.validation import MAX_NAME_LENGTH, MAX_QUERY_LENGTH, clamp_text

# Upper bound on the multi-value fields (relatives, aliases). Generous enough
# for real use, bounded so a crafted request cannot make scoring quadratic.
MAX_LIST_ITEMS = 8

# Plausible human ages. Outside this range the value is treated as a typo and
# dropped rather than turned into a nonsense birth-year window.
MIN_AGE = 1
MAX_AGE = 120

# Name particles that belong to the family name rather than being a middle name
# ("van der Berg", "de la Cruz"). Without this, splitting on whitespace makes
# "van" a middle name and "Berg" the surname, and every surname-scoped check
# then looks for the wrong word.
_NAME_PARTICLES = frozenset(
    {
        "van", "von", "de", "del", "della", "der", "den", "di", "da", "dos",
        "das", "du", "la", "le", "el", "al", "bin", "ibn", "mac", "mc", "st",
    }
)

# Suffixes that are not part of the family name.
_NAME_SUFFIXES = frozenset({"jr", "jr.", "sr", "sr.", "ii", "iii", "iv", "v", "phd", "md"})


def _strip_accents(value: str) -> str:
    """Fold accented characters to their ASCII base ("Muñoz" -> "Munoz").

    Search engines and broker listings disagree about whether to keep accents,
    so comparisons are done on the folded form and both spellings match.
    """
    decomposed = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def normalise(value: str) -> str:
    """Lowercase, accent-fold and collapse whitespace for comparison."""
    return re.sub(r"\s+", " ", _strip_accents(value).lower()).strip()


def _word_pattern(term: str) -> "re.Pattern[str]":
    """Compile ``term`` as a whole-word, case-insensitive pattern.

    Word boundaries matter more than they look. A bare substring test for the
    relative "Ann" matches "announcement", "Anna" and "channel"; a bare test for
    the age "40" matches any page containing "$40". Either one manufactures a
    confident-looking match out of nothing, which for a privacy tool means
    telling someone a stranger's record is theirs.

    ``\\b`` is only meaningful next to a word character, so terms that begin or
    end with punctuation get the boundary omitted on that side.
    """
    escaped = re.escape(term)
    prefix = r"\b" if term[:1].isalnum() else ""
    suffix = r"\b" if term[-1:].isalnum() else ""
    return re.compile(prefix + escaped + suffix, re.IGNORECASE)


@dataclass(frozen=True)
class Factor:
    """One corroborating fact, and the patterns that count as finding it.

    Attributes:
        key: stable machine name, used as a CSS hook and in tests.
        label: human-readable name shown in the UI.
        value: what the user typed, echoed back in the "matched on" explanation.
        weight: how much a match raises confidence. Facts that are unique to an
            individual (phone, email) outweigh facts shared by millions
            (a city).
        patterns: any one matching counts the factor as found.
    """

    key: str
    label: str
    value: str
    weight: int
    patterns: tuple["re.Pattern[str]", ...]

    def matches(self, haystack: str) -> bool:
        """True if any of this factor's patterns occurs in ``haystack``."""
        return any(pattern.search(haystack) for pattern in self.patterns)


@dataclass(frozen=True)
class NameParts:
    """A personal name split into the pieces queries and scoring care about."""

    given: str = ""
    middles: tuple[str, ...] = ()
    family: str = ""
    suffix: str = ""

    @property
    def is_full(self) -> bool:
        """True when both a given and a family name are present."""
        return bool(self.given and self.family)


def split_name(full_name: str) -> NameParts:
    """Split ``full_name`` into given / middle / family / suffix.

    Handles the two forms people actually type: ``"Jane Marie Doe"`` and
    ``"Doe, Jane Marie"``: plus multi-word family names held together by a
    particle ("Jane van der Berg").
    """
    cleaned = re.sub(r"\s+", " ", (full_name or "").strip())
    if not cleaned:
        return NameParts()

    # "Doe, Jane Marie": the part before the comma is the family name.
    if "," in cleaned:
        family_part, _, rest = cleaned.partition(",")
        tokens = rest.split()
        return NameParts(
            given=tokens[0] if tokens else "",
            middles=tuple(tokens[1:]),
            family=family_part.strip(),
        )

    tokens = cleaned.split()

    suffix = ""
    if len(tokens) > 2 and tokens[-1].lower().rstrip(".") in {
        s.rstrip(".") for s in _NAME_SUFFIXES
    }:
        suffix = tokens.pop()

    if len(tokens) == 1:
        # A single token is a family name for matching purposes: a mononym or a
        # surname-only search is far more useful scoped to the surname.
        return NameParts(family=tokens[0], suffix=suffix)

    # Walk back from the end while the preceding token is a particle, so
    # "van der Berg" stays together as the family name.
    family_start = len(tokens) - 1
    while family_start > 1 and tokens[family_start - 1].lower().strip(".") in _NAME_PARTICLES:
        family_start -= 1

    return NameParts(
        given=tokens[0],
        middles=tuple(tokens[1:family_start]),
        family=" ".join(tokens[family_start:]),
        suffix=suffix,
    )


def _clean_list(values: Iterable[str] | None, max_length: int) -> tuple[str, ...]:
    """Clamp, de-duplicate and cap a multi-value field, preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in values or ():
        item = clamp_text(raw, max_length)
        key = normalise(item)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_LIST_ITEMS:
            break
    return tuple(out)


def _phone_digits(value: str) -> str:
    """Return just the digits of a phone number, dropping a country prefix."""
    digits = re.sub(r"\D", "", value or "")
    # US numbers are commonly written with and without the leading 1; compare on
    # the 10-digit national form so both spellings match.
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


def _phone_patterns(value: str) -> tuple["re.Pattern[str]", ...]:
    """Patterns matching a phone number in the formats sites actually print."""
    digits = _phone_digits(value)
    if len(digits) < 7:
        return ()
    if len(digits) == 10:
        area, exchange, line = digits[:3], digits[3:6], digits[6:]
        # One pattern covering (555) 123-4567, 555-123-4567, 555.123.4567,
        # 555 123 4567 and 5551234567: the separators sites vary between.
        spellings = (
            rf"\(?{area}\)?[-.\s]?{exchange}[-.\s]?{line}",
        )
    else:
        spellings = (re.escape(digits),)
    return tuple(re.compile(rf"\b{s}\b") for s in spellings)


def _year_from_age(age: int, today: date | None = None) -> tuple[int, int]:
    """Birth-year window for someone currently ``age`` years old.

    Two years, not one: without a birthday, an age of 40 means born in either of
    the two years straddling today's date.
    """
    current_year = (today or date.today()).year
    return current_year - age - 1, current_year - age


@dataclass(frozen=True)
class IdentityProfile:
    """The person being searched for, plus every fact known to narrow them down.

    Only :attr:`full_name` is required. Every other field is optional and simply
    makes the confidence scoring sharper: the tool must stay useful for
    someone who knows nothing but a name.
    """

    full_name: str = ""
    location: str = ""
    employer: str = ""
    school: str = ""
    email: str = ""
    username: str = ""
    phone: str = ""
    age: str = ""
    relatives: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    _today: date | None = field(default=None, repr=False, compare=False)

    # --- construction -------------------------------------------------------

    @classmethod
    def from_form(cls, form: Mapping[str, str], *, today: date | None = None) -> "IdentityProfile":
        """Build a profile from a Flask ``request.form``-shaped mapping.

        Every field is clamped here so no other layer has to. ``getlist`` is
        used when available (Werkzeug's MultiDict) so repeated fields such as
        ``relatives`` arrive as a list rather than only their last value.
        """
        def one(name: str, limit: int = MAX_QUERY_LENGTH) -> str:
            return clamp_text(form.get(name, ""), limit)

        def many(name: str) -> tuple[str, ...]:
            # getattr on a Mapping yields an untyped value, so the result is
            # coerced to a concrete list[str] here rather than being assigned
            # to a Sequence[str] name the checker cannot verify.
            getlist = getattr(form, "getlist", None)
            if callable(getlist):
                raw: list[str] = [str(value) for value in getlist(name)]
            else:
                text = form.get(name, "")
                # Fall back to comma-separated entry for plain dict callers and
                # for a single text input holding several names.
                raw = text.split(",") if text else []
            return _clean_list(raw, MAX_NAME_LENGTH)

        return cls(
            full_name=one("user_info", MAX_NAME_LENGTH),
            location=one("location"),
            employer=one("employer"),
            school=one("school"),
            email=one("email"),
            username=one("username", MAX_NAME_LENGTH),
            phone=one("phone", 40),
            age=one("age", 8),
            relatives=many("relatives"),
            aliases=many("aliases"),
            _today=today,
        )

    # --- derived name data --------------------------------------------------

    @property
    def parts(self) -> NameParts:
        """The subject's name, split into its components."""
        return split_name(self.full_name)

    @property
    def has_name(self) -> bool:
        """True when there is something worth searching for."""
        return bool(normalise(self.full_name))

    @property
    def core_name(self) -> str:
        """Given plus family name, with any middle name and suffix dropped.

        This is the spelling to scope a site search to. Someone who types
        "Jane Marie Doe" is not listed that way on LinkedIn or Instagram,
        those profiles read "Jane Doe": and ``site:linkedin.com "Jane Marie
        Doe"`` therefore returns nothing while the profile sits there in plain
        sight. Broad searches still use the full name as typed; only the
        scoped passes fall back to this.
        """
        parts = self.parts
        if parts.is_full:
            return f"{parts.given} {parts.family}"
        return re.sub(r"\s+", " ", self.full_name.strip())

    def name_variants(self) -> tuple[str, ...]:
        """Name spellings worth issuing a separate search for, best first.

        Deliberately short. Each variant costs one upstream request against a
        backend that throttles, so this returns the spellings that genuinely
        surface different listings: not every permutation that exists.
        """
        parts = self.parts
        variants: list[str] = []

        def add(value: str) -> None:
            cleaned = re.sub(r"\s+", " ", value).strip()
            if cleaned and normalise(cleaned) not in {normalise(v) for v in variants}:
                variants.append(cleaned)

        # As typed, first: whatever the user wrote is the spelling they expect
        # to see searched for.
        add(self.full_name)

        if parts.is_full:
            # Plain "Given Family". Added unconditionally rather than only when
            # a middle name was given, because someone who types the directory
            # form "Doe, Jane" would otherwise never have the natural spelling
            # searched at all.
            add(f"{parts.given} {parts.family}")
            # "Doe, Jane": how directories and public records index people.
            add(f"{parts.family}, {parts.given}")
            if parts.middles:
                # Middle initial only, the other common listing form.
                add(f"{parts.given} {parts.middles[0][:1]} {parts.family}")

        for alias in self.aliases:
            add(alias)

        return tuple(variants)

    # --- scoring inputs -----------------------------------------------------

    def factors(self) -> tuple[Factor, ...]:
        """Every corroborating fact supplied, as matchable patterns.

        Weights encode how much a match narrows the field. A phone number or an
        email address is effectively unique to one person; an employer or a
        school is shared by thousands; a city is shared by millions. The name
        itself is *not* a factor: every result matches it by construction, so
        counting it would inflate every score equally and distinguish nothing.
        """
        found: list[Factor] = []

        def add(key: str, label: str, value: str, weight: int,
                patterns: Iterable["re.Pattern[str]"]) -> None:
            compiled = tuple(patterns)
            if value and compiled:
                found.append(Factor(key, label, value, weight, compiled))

        if self.location:
            # Each comma-separated component matches on its own, so "Austin, TX"
            # is corroborated by a page naming only the city.
            location_terms = [t.strip() for t in self.location.split(",") if t.strip()]
            add("location", "Location", self.location, 3,
                (_word_pattern(t) for t in location_terms))

        add("employer", "Employer", self.employer, 4,
            (_word_pattern(self.employer),) if self.employer else ())
        add("school", "School", self.school, 3,
            (_word_pattern(self.school),) if self.school else ())

        if self.email:
            # The local part alone is worth matching: sites frequently redact
            # the domain ("jane.doe@...") or list the handle without it.
            local = self.email.partition("@")[0]
            email_patterns = [_word_pattern(self.email)]
            if len(local) >= 4:
                email_patterns.append(_word_pattern(local))
            add("email", "Email address", self.email, 5, email_patterns)

        if self.username and len(self.username) >= 3:
            add("username", "Username", self.username, 4, (_word_pattern(self.username),))

        add("phone", "Phone number", self.phone, 5, _phone_patterns(self.phone))

        age_factor = self._age_factor()
        if age_factor:
            found.append(age_factor)

        for index, relative in enumerate(self.relatives):
            # Match on the whole name when given, else the single token.
            add(f"relative_{index}", "Relative", relative, 4, (_word_pattern(relative),))

        return tuple(found)

    def _age_factor(self) -> Factor | None:
        """Match an age either as a stated age or as the implied birth years.

        A bare number is never matched on its own: "40" appears on nearly every
        page. It only counts when written the way listings write it ("Age 40",
        "40 years old") or as a four-digit birth year, which is specific enough
        to stand alone.
        """
        raw = self.age.strip()
        if not raw.isdigit():
            return None
        age = int(raw)
        if not MIN_AGE <= age <= MAX_AGE:
            return None

        earliest, latest = _year_from_age(age, self._today)
        patterns = [
            re.compile(rf"\bages?\s*:?\s*{age}\b", re.IGNORECASE),
            re.compile(rf"\b{age}\s*(?:years?\s*old|yrs?\.?\s*old|y/?o)\b", re.IGNORECASE),
            re.compile(rf"\b(?:born|b\.)\s*(?:in\s*)?(?:{earliest}|{latest})\b", re.IGNORECASE),
            re.compile(rf"\b(?:{earliest}|{latest})\b"),
        ]
        return Factor("age", "Age", raw, 3, tuple(patterns))

    def surname_patterns(self) -> tuple["re.Pattern[str]", ...]:
        """Patterns proving a result mentions the subject's name at all.

        Used as a floor rather than a bonus: a result that names neither the
        full name nor the surname is search-engine drift, and should be ranked
        as such no matter how many other factors coincidentally appear.
        """
        parts = self.parts
        patterns = []
        if parts.is_full:
            # Given and family name close together, in either order, tolerating
            # a middle name or initial between them.
            given = re.escape(parts.given)
            family = re.escape(parts.family)
            patterns.append(
                re.compile(rf"\b{given}\b[\w.\s'-]{{0,20}}?\b{family}\b", re.IGNORECASE)
            )
            patterns.append(
                re.compile(rf"\b{family}\b\s*,?\s*\b{given}\b", re.IGNORECASE)
            )
        elif normalise(self.full_name):
            patterns.append(_word_pattern(self.full_name))
        return tuple(patterns)

    def describe(self) -> tuple[tuple[str, str], ...]:
        """Label/value pairs of the supplied facts, for showing back to the user.

        A privacy tool must be plain about what it was given; this is what the
        results header renders so the search is never a black box.
        """
        pairs: list[tuple[str, str]] = []
        for label, value in (
            ("Name", self.full_name),
            ("Location", self.location),
            ("Employer", self.employer),
            ("School", self.school),
            ("Email", self.email),
            ("Username", self.username),
            ("Phone", self.phone),
            ("Age", self.age),
        ):
            if value:
                pairs.append((label, value))
        if self.relatives:
            pairs.append(("Relatives", ", ".join(self.relatives)))
        if self.aliases:
            pairs.append(("Also known as", ", ".join(self.aliases)))
        return tuple(pairs)
