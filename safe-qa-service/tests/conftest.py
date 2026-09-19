from __future__ import annotations

import hashlib
import json
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from safe_qa_service.app import app, get_ledger
from safe_qa_service.ledger import LedgerReceipt, LedgerVerification

TEST_TOKEN = "local-test-token"


class FakeLedger:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def append(self, **event: object) -> LedgerReceipt:
        self.events.append(dict(event))
        return LedgerReceipt(
            event_id=UUID("11111111-1111-4111-8111-111111111111"),
            sequence_id=len(self.events),
            event_hash="a" * 64,
        )

    def healthcheck(self) -> bool:
        return True

    def verify_chain(self) -> LedgerVerification:
        return LedgerVerification(valid=True, event_count=len(self.events))


@pytest.fixture
def fake_ledger() -> FakeLedger:
    return FakeLedger()


@pytest.fixture(autouse=True)
def configure_test_boundary(monkeypatch: pytest.MonkeyPatch, fake_ledger: FakeLedger):
    token_hash = hashlib.sha256(TEST_TOKEN.encode()).hexdigest()
    principals = {
        token_hash: {
            "subject": "test-principal",
            "scopes": ["evaluate", "audit:read"],
        }
    }
    monkeypatch.setenv("SAFE_QA_AUTH_TOKEN_HASHES_JSON", json.dumps(principals))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    app.dependency_overrides[get_ledger] = lambda: fake_ledger
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TEST_TOKEN}"}
