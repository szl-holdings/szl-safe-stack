"""Disposable SQLite regression contracts; no live databases or providers."""
from __future__ import annotations
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from frontier_gateway.ledger import ReceiptLedger, LedgerIntegrityError, LedgerUnavailableError

class ReadinessSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='szl-readiness-regression-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'synthetic.sqlite3'
        self.ledger = ReceiptLedger(self.path)
        self.ledger.append({'synthetic': 1})
        self.ledger.append({'synthetic': 2})
        self.ledger.append({'synthetic': 3})
        self.ledger.verify()
        for target in ('socket.create_connection', 'socket.socket.connect'):
            guard = patch(target, side_effect=AssertionError('network forbidden in regression'))
            guard.start(); self.addCleanup(guard.stop)

    def tamper(self, sequence=3, field='canonical_event', value='{"tampered":true}'):
        if field not in {'canonical_event','event_id','created_at','previous_hash','hash_version'}:
            raise AssertionError('test field not allowlisted')
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute('DROP TRIGGER receipts_no_update')
            connection.execute(f'UPDATE receipts SET {field}=? WHERE sequence=?', (value, sequence))

    def test_cached_tail_body_corruption_is_rejected(self):
        self.tamper()
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify_head()

    def test_cached_earlier_body_corruption_is_rejected(self):
        self.tamper(sequence=1)
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify_head()

    def test_cached_event_id_corruption_is_rejected(self):
        self.tamper(field='event_id', value='not-a-uuid')
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify_head()

    def test_cached_timestamp_corruption_is_rejected(self):
        self.tamper(field='created_at', value='not-a-timestamp')
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify_head()

    def test_failed_full_audit_cannot_leave_ready_cache(self):
        self.tamper(sequence=1)
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify()
        self.assertIsNone(self.ledger._verified_state)
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify_head()

    def test_failed_head_check_clears_cache(self):
        self.tamper(field='previous_hash', value='f'*64)
        with self.assertRaises(LedgerIntegrityError): self.ledger.verify_head()
        self.assertIsNone(self.ledger._verified_state)

    def test_missing_database_read_never_recreates_it(self):
        self.path.unlink()
        with self.assertRaises(LedgerUnavailableError): self.ledger.verify()
        self.assertFalse(self.path.exists())

    def test_stable_cached_path_does_not_scan_count(self):
        # Available only after the audited implementation adds a read-only reader.
        self.assertTrue(hasattr(self.ledger, '_reader'), 'read-only reader missing')
        queries=[]; original=self.ledger._reader
        def reader():
            connection=original(); connection.set_trace_callback(queries.append); return connection
        with patch.object(self.ledger, '_reader', side_effect=reader):
            self.ledger.verify_head()
        self.assertFalse(any('COUNT(' in q.upper() for q in queries), queries)

    def test_stable_cache_avoids_full_rehash(self):
        self.ledger.verify()
        with patch.object(self.ledger, 'verify', side_effect=AssertionError('unexpected full audit')):
            self.assertEqual(self.ledger.verify_head()['receipt_count'], 3)

    def test_expired_cache_requires_full_audit(self):
        self.assertTrue(hasattr(self.ledger, '_verified_at'), 'audit age missing')
        self.ledger._verified_at = -1.0
        with patch.object(self.ledger, 'verify', wraps=self.ledger.verify) as audit:
            self.ledger.verify_head()
        self.assertEqual(audit.call_count, 1)

    def test_future_cache_timestamp_requires_full_audit(self):
        self.assertTrue(hasattr(self.ledger, '_verified_at'), 'audit age missing')
        self.ledger._verified_at = 1e30
        with patch.object(self.ledger, 'verify', wraps=self.ledger.verify) as audit:
            self.ledger.verify_head()
        self.assertEqual(audit.call_count, 1)

    def test_external_valid_append_preserves_continuity(self):
        other=ReceiptLedger(self.path); receipt=other.append({'synthetic': 4})
        result=self.ledger.verify_head()
        self.assertEqual(result['receipt_count'],4)
        self.assertEqual(result['head_hash'],receipt['event_hash'])

    def test_valid_replacement_chain_is_not_silently_adopted(self):
        other_path=Path(self.temp.name)/'replacement.sqlite3'
        other=ReceiptLedger(other_path)
        for n in range(3): other.append({'different_synthetic':n})
        for path in (self.path,other_path):
            with closing(sqlite3.connect(path)) as c: c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        shutil.copyfile(other_path,self.path)
        with self.assertRaises(LedgerIntegrityError):self.ledger.verify_head()

    def test_repeated_audit_rejection_preserves_anchor(self):
        self.assertTrue(hasattr(self.ledger,'_continuity_anchor'), 'continuity anchor missing')
        anchor=self.ledger._continuity_anchor
        self.tamper(sequence=1)
        for _ in range(2):
            with self.assertRaises(LedgerIntegrityError):self.ledger.verify()
        self.assertEqual(self.ledger._continuity_anchor,anchor)

    def test_append_verifies_inside_write_transaction(self):
        self.assertTrue(hasattr(self.ledger,'_verify_connection'), 'single-transaction verifier missing')
        original=self.ledger._verify_connection; observed=[]
        def verify(connection):
            observed.append(connection.in_transaction); return original(connection)
        with patch.object(self.ledger,'_verify_connection',side_effect=verify):
            self.ledger.append({'synthetic':4})
        self.assertTrue(observed and all(observed))

    def test_invalid_chain_cannot_be_extended(self):
        self.tamper(sequence=1)
        with self.assertRaises(LedgerIntegrityError):self.ledger.append({'must_not_append':True})
        with closing(sqlite3.connect(self.path)) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM receipts').fetchone()[0],3)

    def test_concurrent_appends_remain_contiguous(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda n:self.ledger.append({'synthetic_concurrent':n}),range(12)))
        self.assertEqual(self.ledger.verify()['receipt_count'],15)

    def test_restart_replays_identical_chain(self):
        expected=self.ledger.verify()
        restarted=ReceiptLedger(self.path)
        self.assertEqual(restarted.verify(),expected)

    def test_unchanged_empty_chain_is_cacheable(self):
        empty=ReceiptLedger(Path(self.temp.name)/'empty.sqlite3'); empty.verify()
        with patch.object(empty,'verify',side_effect=AssertionError('unexpected empty rehash')):
            self.assertEqual(empty.verify_head()['receipt_count'],0)

    def test_runtime_result_shape_preserved(self):
        result=self.ledger.verify_head()
        self.assertEqual(set(result),{'schema_version','hash_version','status','receipt_count','head_hash'})
        self.assertEqual(result['status'],'VERIFIED')
        json.dumps(result,allow_nan=False)

if __name__=='__main__':unittest.main(verbosity=2)
