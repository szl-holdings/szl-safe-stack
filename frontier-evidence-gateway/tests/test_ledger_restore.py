from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import frontier_gateway.ledger as ledger_module
from frontier_gateway.ledger import (
    ReceiptLedger,
    isolated_restore_measurement,
    validate_restore_measurement,
)


def _quiescent_ledger(directory: Path, *, receipts: int) -> Path:
    database = directory / "receipts.sqlite3"
    ledger = ReceiptLedger(database)
    for index in range(receipts):
        ledger.append({"schema_version": "szl.frontier.receipt_event.v1", "n": index})
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()
    return database


class IsolatedRestoreTests(unittest.TestCase):
    def test_synthetic_restore_matches_schema_content_chain_and_clock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _quiescent_ledger(root, receipts=2)
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            recovery = datetime(2026, 10, 9, 16, 0, tzinfo=timezone.utc)
            started = recovery + timedelta(seconds=5)
            completed = started + timedelta(seconds=3)
            result = isolated_restore_measurement(
                source,
                recovery_point_at=recovery,
                started_at=started,
                clock=lambda: completed,
            )
            self.assertFalse(result["production_approval"])
            self.assertIsNone(result["signature"])
            self.assertEqual(result["engine"], "sqlite")
            self.assertEqual(result["postgresql_ledger"], "NOT_APPLICABLE")
            self.assertEqual(result["measurement_verdict"], "PASS", result["measurement_detail"])
            measurement = result["measurement"]
            self.assertEqual(validate_restore_measurement(measurement), (
                "PASS",
                "isolated restore run_id=restore-gateway-synthetic rto_seconds=3.0 rpo_seconds=5.0",
            ))
            self.assertEqual(measurement["rto_seconds"], 3.0)
            self.assertEqual(measurement["rpo_seconds"], 5.0)
            self.assertEqual(measurement["validation"]["integrity_check"], "ok")
            self.assertEqual(measurement["validation"]["foreign_key_violation_count"], 0)
            self.assertTrue(measurement["validation"]["receipt_chain_valid"])
            self.assertEqual(measurement["validation"]["receipt_count"], 2)
            self.assertEqual(
                measurement["validation"]["source_schema_sha256"],
                measurement["validation"]["restored_schema_sha256"],
            )
            self.assertEqual(
                measurement["validation"]["source_content_sha256"],
                measurement["validation"]["restored_content_sha256"],
            )
            self.assertEqual(
                measurement["validation"]["source_row_counts"],
                measurement["validation"]["restored_row_counts"],
            )
            self.assertEqual(measurement["source"]["database_sha256_before"], source_hash)
            self.assertEqual(measurement["source"]["database_sha256_after"], source_hash)
            self.assertTrue(measurement["source"]["unchanged"])
            self.assertTrue(measurement["source"]["query_only"])
            for suffix in ("-wal", "-shm", "-journal"):
                pair = measurement["source"]["sidecars"][suffix]
                self.assertEqual(pair["before"], pair["after"])
                self.assertFalse(pair["before"]["exists"])
            self.assertTrue(measurement["failure_scenarios"]["corrupt_backup_rejected"])
            self.assertTrue(measurement["failure_scenarios"]["missing_backup_rejected"])
            self.assertEqual(measurement["restore_target"]["production_writes"], 0)
            self.assertTrue(measurement["restore_target"]["cleaned_up"])
            self.assertFalse(measurement["restore_target"]["path_disclosed"])
            rendered = str(result)
            self.assertNotIn("szl-gateway-restore-", rendered)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), source_hash)
            self.assertEqual(
                measurement["tool_sha256"],
                hashlib.sha256(Path(ledger_module.__file__).read_bytes()).hexdigest(),
            )

    def test_rto_tamper_and_extra_key_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _quiescent_ledger(Path(directory), receipts=1)
            recovery = datetime(2026, 10, 9, 16, 0, tzinfo=timezone.utc)
            started = recovery + timedelta(seconds=5)
            result = isolated_restore_measurement(
                source,
                recovery_point_at=recovery,
                started_at=started,
                clock=lambda: started + timedelta(seconds=3),
            )
        measurement = result["measurement"]
        self.assertEqual(result["measurement_verdict"], "PASS")
        tampered = dict(measurement)
        tampered["rto_seconds"] = 0
        verdict, detail = validate_restore_measurement(tampered)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("RTO", detail)
        tampered = dict(measurement)
        tampered["production_approval"] = True
        verdict, detail = validate_restore_measurement(tampered)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("shape", detail)

    def test_empty_sidecars_stay_empty_and_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _quiescent_ledger(Path(directory), receipts=1)
            sidecars = [Path(str(source) + suffix) for suffix in ("-wal", "-shm", "-journal")]
            for path in sidecars:
                path.write_bytes(b"")
            recovery = datetime(2026, 10, 9, 16, 0, tzinfo=timezone.utc)
            started = recovery + timedelta(seconds=4)
            result = isolated_restore_measurement(
                source,
                recovery_point_at=recovery,
                started_at=started,
                clock=lambda: started + timedelta(seconds=2),
            )
            self.assertEqual(result["measurement_verdict"], "PASS", result["measurement_detail"])
            for suffix, path in zip(("-wal", "-shm", "-journal"), sidecars, strict=True):
                pair = result["measurement"]["source"]["sidecars"][suffix]
                self.assertTrue(pair["before"]["exists"])
                self.assertEqual(pair["before"], pair["after"])
                self.assertEqual(pair["before"]["size_bytes"], 0)
                self.assertEqual(path.read_bytes(), b"")
            self.assertFalse(result["production_approval"])

    def test_empty_chain_is_not_a_passing_restore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = _quiescent_ledger(Path(directory), receipts=0)
            recovery = datetime(2026, 10, 9, 16, 0, tzinfo=timezone.utc)
            result = isolated_restore_measurement(
                source,
                recovery_point_at=recovery,
                started_at=recovery + timedelta(seconds=1),
                clock=lambda: recovery + timedelta(seconds=2),
            )
        self.assertFalse(result["production_approval"])
        self.assertEqual(result["measurement_verdict"], "FAIL")
        self.assertIsNotNone(result["measurement"])
        self.assertFalse(result["measurement"]["validation"]["receipt_chain_valid"])

    def test_live_sidecar_and_postgres_script_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _quiescent_ledger(root, receipts=1)
            wal = Path(str(source) + "-wal")
            wal.write_bytes(b"live-wal-frame")
            before = wal.read_bytes()
            recovery = datetime(2026, 10, 9, 16, 0, tzinfo=timezone.utc)
            result = isolated_restore_measurement(
                source,
                recovery_point_at=recovery,
                started_at=recovery + timedelta(seconds=1),
                clock=lambda: recovery + timedelta(seconds=2),
            )
            self.assertEqual(result["measurement_verdict"], "FAIL")
            self.assertIsNone(result["measurement"])
            self.assertIn("sidecar", result["measurement_detail"])
            self.assertEqual(wal.read_bytes(), before)
            self.assertFalse(result["production_approval"])

        script = (
            Path(__file__).resolve().parents[2]
            / "safe-qa-service"
            / "db"
            / "migrations"
            / "001_audit_ledger.sql"
        )
        script_hash = hashlib.sha256(script.read_bytes()).hexdigest()
        recovery = datetime(2026, 10, 9, 16, 0, tzinfo=timezone.utc)
        refused = isolated_restore_measurement(
            script,
            recovery_point_at=recovery,
            started_at=recovery + timedelta(seconds=1),
            clock=lambda: recovery + timedelta(seconds=2),
        )
        self.assertEqual(refused["measurement_verdict"], "FAIL")
        self.assertIsNone(refused["measurement"])
        self.assertIn("PostgreSQL", refused["measurement_detail"])
        self.assertEqual(hashlib.sha256(script.read_bytes()).hexdigest(), script_hash)
        self.assertFalse(refused["production_approval"])


if __name__ == "__main__":
    unittest.main()
