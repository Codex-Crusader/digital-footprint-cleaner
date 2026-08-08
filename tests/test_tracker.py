# pytest is a test-only dependency (requirements-dev.txt), not a runtime one.
# noinspection PyPackageRequirements
import pytest

from utils import tracker


@pytest.fixture
def db(tmp_path):
    """A throwaway database file, so no test ever touches the real one."""
    return tmp_path / "tracker.sqlite3"


def test_init_creates_database_file(db):
    tracker.init_db(db)
    assert db.exists()


def test_schema_is_created_on_demand_without_explicit_init(db):
    # Every entry point opens its own connection and guarantees the schema.
    assert tracker.list_requests(path=db) == []


def test_add_and_list_round_trip(db):
    request_id = tracker.add_request(
        "Spokeo",
        site_domain="spokeo.com",
        opt_out_url="https://www.spokeo.com/optout",
        data_types=["address", "phone"],
        legal_basis="ccpa",
        notes="Submitted via web form",
        path=db,
    )
    assert request_id > 0

    rows = tracker.list_requests(path=db)
    assert len(rows) == 1
    row = rows[0]
    assert row["site_name"] == "Spokeo"
    assert row["data_types"] == ["address", "phone"]  # stored as JSON, read back as list
    assert row["status"] == tracker.DEFAULT_STATUS
    assert row["created_at"] and row["updated_at"]


def test_add_request_rejects_blank_site_name(db):
    with pytest.raises(ValueError):
        tracker.add_request("   ", path=db)


def test_add_request_rejects_unknown_status(db):
    with pytest.raises(ValueError):
        tracker.add_request("Spokeo", status="teleported", path=db)


def test_update_status_and_notes(db):
    request_id = tracker.add_request("Radaris", path=db)
    assert tracker.update_request(request_id, status="sent", path=db) is True

    row = tracker.get_request(request_id, path=db)
    assert row is not None
    assert row["status"] == "sent"

    assert tracker.update_request(request_id, notes="They replied", path=db) is True
    row = tracker.get_request(request_id, path=db)
    assert row is not None
    assert row["notes"] == "They replied"
    assert row["status"] == "sent"  # unchanged by a notes-only update


def test_update_rejects_unknown_status(db):
    request_id = tracker.add_request("Radaris", path=db)
    with pytest.raises(ValueError):
        tracker.update_request(request_id, status="nope", path=db)


def test_update_missing_row_returns_false(db):
    assert tracker.update_request(9999, status="sent", path=db) is False


def test_update_with_nothing_to_change_returns_false(db):
    request_id = tracker.add_request("Radaris", path=db)
    assert tracker.update_request(request_id, path=db) is False


def test_get_missing_request_returns_none(db):
    assert tracker.get_request(4242, path=db) is None


def test_list_can_filter_by_status(db):
    tracker.add_request("A", status="todo", path=db)
    tracker.add_request("B", status="removed", path=db)
    assert len(tracker.list_requests(path=db)) == 2
    assert len(tracker.list_requests(status="removed", path=db)) == 1
    assert tracker.list_requests(status="removed", path=db)[0]["site_name"] == "B"


def test_delete_request(db):
    request_id = tracker.add_request("Spokeo", path=db)
    assert tracker.delete_request(request_id, path=db) is True
    assert tracker.delete_request(request_id, path=db) is False
    assert tracker.list_requests(path=db) == []


def test_purge_all_forgets_everything(db):
    for name in ("A", "B", "C"):
        tracker.add_request(name, path=db)
    assert tracker.purge_all(path=db) == 3
    assert tracker.list_requests(path=db) == []


def test_summary_counts_open_and_removed(db):
    tracker.add_request("A", status="todo", path=db)
    tracker.add_request("B", status="sent", path=db)
    tracker.add_request("C", status="removed", path=db)
    tracker.add_request("D", status="reappeared", path=db)

    stats = tracker.summary(path=db)
    assert stats["total"] == 4
    assert stats["removed"] == 1
    # 'reappeared' still needs action, so it counts as open alongside todo/sent.
    assert stats["open"] == 3
    assert stats["by_status"]["removed"] == 1


def test_summary_on_empty_database(db):
    stats = tracker.summary(path=db)
    assert stats["total"] == 0
    assert stats["open"] == 0
    assert set(stats["by_status"]) == set(tracker.STATUSES)


def test_long_text_is_clamped(db):
    request_id = tracker.add_request("X" * 999, notes="N" * 999, path=db)
    row = tracker.get_request(request_id, path=db)
    assert row is not None
    assert len(row["site_name"]) <= 200
    assert len(row["notes"]) <= 500


def test_db_path_respects_environment_override(monkeypatch, tmp_path):
    custom = tmp_path / "elsewhere" / "custom.sqlite3"
    monkeypatch.setenv("DFC_DB_PATH", str(custom))
    assert tracker.db_path() == custom

    # The parent directory is created on demand rather than assumed to exist.
    tracker.init_db()
    assert custom.exists()


def test_default_path_is_used_when_override_is_blank(monkeypatch):
    monkeypatch.setenv("DFC_DB_PATH", "   ")
    assert tracker.db_path().name == "tracker.sqlite3"
    assert tracker.db_path().parent.name == "instance"
