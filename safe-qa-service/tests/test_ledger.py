from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from safe_qa_service.ledger import GENESIS_HASH, canonical_event_bytes, event_hash


def _event() -> dict:
    return {
        "event_id": UUID("11111111-1111-4111-8111-111111111111"),
        "occurred_at": datetime(2026, 8, 9, 12, 0, 0, 123456, tzinfo=UTC),
        "actor_subject": "reviewer@example.invalid",
        "action": "evaluation.withheld",
        "request_id": UUID("22222222-2222-4222-8222-222222222222"),
        "payload": {"z": 1, "a": {"release_authorized": False}},
        "previous_hash": GENESIS_HASH,
    }


def test_canonical_event_is_deterministic() -> None:
    first = canonical_event_bytes(**_event())
    second = canonical_event_bytes(**_event())
    assert first == second
    assert b'"release_authorized":false' in first


def test_any_payload_change_changes_hash() -> None:
    original = _event()
    modified = _event()
    modified["payload"] = {"z": 2, "a": {"release_authorized": False}}
    assert event_hash(**original) != event_hash(**modified)
