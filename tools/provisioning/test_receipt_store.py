import contextlib
import multiprocessing
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from receipt_store import ReceiptStore, StoreError


PRINCIPAL = bytes([1]) * 32
ANCHOR = bytes([2]) * 72
RESOURCE = bytes([3]) * 32
OPERATION = bytes([4]) * 16
DIGEST = bytes([5]) * 32
PAYLOAD = b"complete\x00\xfftelemetry"


class Authority:
    def __init__(self):
        self.lock = threading.RLock()
        self.enabled = True
        self.anchor = ANCHOR
        self.resources = {RESOURCE}

    @contextlib.contextmanager
    def authorize(self, principal, anchor, resource, action):
        with self.lock:
            if (not self.enabled or principal != PRINCIPAL or anchor != self.anchor
                    or resource not in self.resources
                    or action not in {"telemetry", "desired", "applied", "management"}):
                raise StoreError("unauthorized")
            yield


def crash_writer(path, stage):
    store = ReceiptStore(Path(path), Authority().authorize)
    def cut(at):
        if at == stage:
            os._exit(17)
    store.commit(PRINCIPAL, ANCHOR, OPERATION, RESOURCE, 42, DIGEST, PAYLOAD, cut)


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "receipts.db"
        self.authority = Authority()
        self.store = ReceiptStore(self.path, self.authority.authorize)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def commit(self, **overrides):
        values = dict(principal=PRINCIPAL, anchor=ANCHOR, operation=OPERATION,
                      resource=RESOURCE, content_format=42, digest=DIGEST, payload=PAYLOAD)
        values.update(overrides)
        return self.store.commit(**values)

    def test_duplicate_after_reopen_returns_complete_receipt(self):
        receipt = self.commit()
        checkpoint = self.store.checkpoint()
        self.store.close()
        self.store = ReceiptStore(self.path, self.authority.authorize, checkpoint)
        self.assertEqual(receipt, self.commit())
        self.assertEqual(56, len(receipt))
        self.assertEqual((PAYLOAD,), self.store.db.execute("SELECT payload FROM receipts").fetchone())
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])

    def test_full_content_conflicts_are_refused(self):
        self.commit()
        for changes in [dict(payload=b"different"), dict(digest=bytes(32)), dict(content_format=None), dict(resource=bytes(32))]:
            with self.subTest(changes=changes), self.assertRaises(StoreError):
                self.commit(**changes)

    def test_revocation_and_cross_device_refuse_cached_receipt(self):
        self.commit()
        self.authority.enabled = False
        with self.assertRaises(StoreError):
            self.commit()
        self.authority.enabled = True
        with self.assertRaises(StoreError):
            self.commit(principal=bytes(32))
        with self.assertRaises(StoreError):
            self.commit(anchor=bytes(72))

    def test_lost_commit_ack_is_recoverable(self):
        def lose_ack(stage):
            if stage == "after_commit":
                raise OSError("acknowledgement lost")
        with self.assertRaises(OSError):
            self.commit(cut=lose_ack)
        self.assertEqual(1, int.from_bytes(self.commit()[48:], "big"))

    def test_policy_fence_covers_commit_and_revocation_refuses_retry(self):
        attempted = threading.Event()
        revoked = threading.Event()

        def revoke():
            attempted.set()
            with self.authority.lock:
                self.authority.enabled = False
                revoked.set()

        worker = None

        def cut(stage):
            nonlocal worker
            if stage == "before_commit":
                worker = threading.Thread(target=revoke)
                worker.start()
                self.assertTrue(attempted.wait(2), "revocation worker did not start")
            self.assertFalse(revoked.is_set(), "policy fence released before commit returned")

        try:
            receipt = self.commit(cut=cut)
        finally:
            if worker is not None:
                worker.join(2)
                self.assertFalse(worker.is_alive(), "revocation worker remained blocked")
        self.assertTrue(revoked.is_set())
        self.assertEqual(1, int.from_bytes(receipt[48:], "big"))
        with self.assertRaises(StoreError):
            self.commit()
        self.assertEqual(1, self.store.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])

    def test_process_crashes_at_commit_boundaries(self):
        self.store.close()
        for stage, expected_rows in [("before_commit", 0), ("after_commit", 1)]:
            with self.subTest(stage=stage):
                path = Path(self.temp.name) / (stage + ".db")
                child = multiprocessing.get_context("spawn").Process(target=crash_writer, args=(str(path), stage))
                child.start()
                child.join(10)
                if child.is_alive():
                    child.kill()
                    child.join()
                    self.fail("crash probe timed out")
                self.assertEqual(17, child.exitcode)
                recovered = ReceiptStore(path, self.authority.authorize)
                self.assertEqual(expected_rows, recovered.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
                result = recovered.commit(PRINCIPAL, ANCHOR, OPERATION, RESOURCE, 42, DIGEST, PAYLOAD)
                self.assertEqual(1, int.from_bytes(result[48:], "big"))
                recovered.close()
        self.store = ReceiptStore(self.path, self.authority.authorize)

    def test_backup_restore_requires_independent_checkpoint(self):
        self.store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        backup = Path(self.temp.name) / "old.db"
        shutil.copyfile(self.path, backup)
        self.commit()
        latest = self.store.checkpoint()
        with self.assertRaises(StoreError):
            ReceiptStore(backup, self.authority.authorize, latest)

    def test_capacity_and_payload_bounds_preserve_existing_receipts(self):
        self.commit()
        self.store.MAX_ROWS = 1
        with self.assertRaises(StoreError):
            self.commit(operation=bytes(16))
        with self.assertRaises(StoreError):
            self.commit(payload=bytes(1025))
        self.assertEqual(1, int.from_bytes(self.commit()[48:], "big"))

    def test_desired_and_applied_versions_are_monotonic_and_isolated(self):
        self.store.set_desired(PRINCIPAL, ANCHOR, RESOURCE, 1, b"configuration\x00\xff")
        self.assertEqual((1, b"configuration\x00\xff"), self.store.get_desired(PRINCIPAL, ANCHOR, RESOURCE))
        self.store.report_applied(PRINCIPAL, ANCHOR, RESOURCE, 1)
        with self.assertRaises(StoreError):
            self.store.set_desired(PRINCIPAL, ANCHOR, RESOURCE, 1, b"changed")
        with self.assertRaises(StoreError):
            self.store.report_applied(PRINCIPAL, ANCHOR, RESOURCE, 2)
        with self.assertRaises(StoreError):
            self.store.get_desired(bytes(32), ANCHOR, RESOURCE)
        second_resource = bytes([6]) * 32
        self.authority.resources.add(second_resource)
        self.assertIsNone(self.store.get_desired(PRINCIPAL, ANCHOR, second_resource))
        self.store.set_desired(PRINCIPAL, ANCHOR, second_resource, 2, b"separate resource")
        self.assertEqual((1, b"configuration\x00\xff"), self.store.get_desired(PRINCIPAL, ANCHOR, RESOURCE))
        self.authority.enabled = False
        with self.assertRaises(StoreError):
            self.store.report_applied(PRINCIPAL, ANCHOR, RESOURCE, 1)


if __name__ == "__main__":
    unittest.main()
