from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import frontier_gateway.ledger as ledger_module


class RestoreReadBoundTests(unittest.TestCase):
    def _source(self, root: Path) -> Path:
        source = root / "receipts.sqlite3"
        ledger_module.ReceiptLedger(source).append({"case": "bounded-restore"})
        connection = sqlite3.connect(source)
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()
        return source

    def _restore(self, source: Path):
        now = datetime(2026, 10, 16, tzinfo=timezone.utc)
        return ledger_module.isolated_restore_measurement(
            source, recovery_point_at=now, started_at=now, clock=lambda: now
        )

    @contextmanager
    def _bounded_reads(self, watched: Path, *, grow_on: int | None = None,
                       fail_on: int | None = None):
        """Reject an unbounded request before the real stream can allocate it."""
        original_open = Path.open
        observed = []
        open_count = 0
        limit = ledger_module.MAX_RESTORE_SOURCE_BYTES + 1

        class WatchedStream:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                self.stream.__enter__()
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def read(self, size=-1):
                if not isinstance(size, int) or not 0 <= size <= limit:
                    raise AssertionError(f"unbounded restore read requested: {size}")
                value = self.stream.read(size)
                observed.append((size, len(value)))
                return value

        def open_checked(path, mode="r", *args, **kwargs):
            nonlocal open_count
            if path == watched and mode == "rb":
                open_count += 1
                if open_count == fail_on:
                    raise OSError("synthetic source reread failure")
                if open_count == grow_on:
                    with original_open(path, "ab") as stream:
                        stream.truncate(limit + 4096)
                return WatchedStream(original_open(path, mode, *args, **kwargs))
            return original_open(path, mode, *args, **kwargs)

        with patch.object(Path, "open", open_checked):
            yield observed

    def _assert_refused(self, result):
        self.assertEqual(result["measurement_verdict"], "FAIL", result)
        self.assertFalse(result["production_approval"])
        self.assertIsNone(result["measurement"])

    def test_oversize_source_is_bounded_before_any_restore_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "oversize.sqlite3"
            with source.open("wb") as stream:
                stream.truncate(ledger_module.MAX_RESTORE_SOURCE_BYTES * 4)
            with self._bounded_reads(source) as reads, patch.object(
                ledger_module.tempfile, "TemporaryDirectory"
            ) as directory_factory:
                self._assert_refused(self._restore(source))
            directory_factory.assert_not_called()
            self.assertEqual(reads, [(5_000_001, 5_000_001)])

    def test_oversize_sidecars_are_bounded_before_restore_directory(self):
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(sidecar=suffix), tempfile.TemporaryDirectory() as directory:
                source = self._source(Path(directory))
                sidecar = Path(str(source) + suffix)
                with sidecar.open("wb") as stream:
                    stream.truncate(ledger_module.MAX_RESTORE_SOURCE_BYTES * 4)
                with self._bounded_reads(sidecar) as reads, patch.object(
                    ledger_module.tempfile, "TemporaryDirectory"
                ) as directory_factory:
                    self._assert_refused(self._restore(source))
                directory_factory.assert_not_called()
                self.assertEqual(reads, [(5_000_001, 5_000_001)])

    def test_growth_between_attestation_and_source_reread_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(Path(directory))
            with self._bounded_reads(source, grow_on=2) as reads, patch.object(
                ledger_module.tempfile, "TemporaryDirectory"
            ) as directory_factory:
                self._assert_refused(self._restore(source))
            directory_factory.assert_not_called()
            self.assertEqual(len(reads), 2)
            self.assertEqual(reads[-1], (5_000_001, 5_000_001))

    def test_growth_before_final_source_attestation_is_bounded_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(Path(directory))
            real_directory = tempfile.TemporaryDirectory
            created = []

            def track_directory(*args, **kwargs):
                temporary = real_directory(*args, **kwargs)
                created.append(Path(temporary.name))
                return temporary

            with self._bounded_reads(source, grow_on=3) as reads, patch.object(
                ledger_module.tempfile, "TemporaryDirectory", track_directory
            ):
                self._assert_refused(self._restore(source))
            self.assertEqual(len(reads), 3)
            self.assertEqual(reads[-1], (5_000_001, 5_000_001))
            self.assertEqual(len(created), 1)
            self.assertFalse(created[0].exists())

    def test_empty_and_exact_limit_files_remain_attestable(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.sqlite3"
            for size in (0, ledger_module.MAX_RESTORE_SOURCE_BYTES):
                with self.subTest(size=size):
                    source.write_bytes(b"x" * size)
                    with self._bounded_reads(source) as reads:
                        observed = ledger_module._attest_file(source)
                    self.assertEqual(observed["size_bytes"], size)
                    self.assertEqual(observed["sha256"], hashlib.sha256(b"x" * size).hexdigest())
                    self.assertEqual(reads, [(5_000_001, size)])

    def test_reread_io_error_is_refused_before_restore_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self._source(Path(directory))
            with self._bounded_reads(source, fail_on=2), patch.object(
                ledger_module.tempfile, "TemporaryDirectory"
            ) as directory_factory:
                self._assert_refused(self._restore(source))
            directory_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
