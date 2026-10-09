import hashlib
import sqlite3
from pathlib import Path


class StoreError(Exception):
    pass


class ReceiptStore:
    MAX_PAYLOAD = 1024
    MAX_ROWS = 4096

    def __init__(self, path: Path, authorize, expected_checkpoint=None):
        self.authorize = authorize
        self.db = sqlite3.connect(path, isolation_level=None, timeout=0.1)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS receipts ("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT, principal BLOB NOT NULL,"
            "operation BLOB NOT NULL, resource BLOB NOT NULL, format INTEGER,"
            "digest BLOB NOT NULL, payload BLOB NOT NULL,"
            "UNIQUE(principal, operation))"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS desired (principal BLOB NOT NULL, resource BLOB NOT NULL,"
            "version INTEGER NOT NULL, payload BLOB NOT NULL, applied INTEGER NOT NULL,"
            "PRIMARY KEY(principal, resource))"
        )
        if expected_checkpoint is not None and self.checkpoint() != expected_checkpoint:
            self.db.close()
            raise StoreError("restore requires authoritative reconciliation")

    def close(self):
        self.db.close()

    def checkpoint(self):
        digest = hashlib.sha256(b"coaptic host receipt ledger v1")
        for row in self.db.execute(
            "SELECT sequence,principal,operation,resource,format,digest,payload "
            "FROM receipts ORDER BY sequence"
        ):
            for value in row:
                if value is None:
                    encoded = b"n"
                elif isinstance(value, int):
                    encoded = b"i" + value.to_bytes(8, "big")
                else:
                    encoded = b"b" + value
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
        for row in self.db.execute(
            "SELECT principal,resource,version,payload,applied FROM desired ORDER BY principal,resource"
        ):
            for value in row:
                encoded = value.to_bytes(8, "big") if isinstance(value, int) else value
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
        return digest.digest()

    def commit(self, principal, anchor, operation, resource, content_format, digest, payload,
               cut=None):
        if (len(principal) != 32 or len(anchor) != 72 or len(operation) != 16
                or len(resource) != 32 or len(digest) != 32
                or len(payload) > self.MAX_PAYLOAD
                or (content_format is not None
                    and (not isinstance(content_format, int) or not 0 <= content_format <= 65535))):
            raise StoreError("invalid complete operation")
        with self.authorize(principal, anchor, resource, "telemetry"):
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT sequence,resource,format,digest,payload FROM receipts "
                    "WHERE principal=? AND operation=?", (principal, operation)
                ).fetchone()
                if row is not None:
                    if row[1:] != (resource, content_format, digest, payload):
                        raise StoreError("operation content conflict")
                    sequence = row[0]
                else:
                    if self.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] >= self.MAX_ROWS:
                        raise StoreError("receipt capacity")
                    sequence = self.db.execute(
                        "INSERT INTO receipts(principal,operation,resource,format,digest,payload) "
                        "VALUES(?,?,?,?,?,?)",
                        (principal, operation, resource, content_format, digest, payload)
                    ).lastrowid
                if cut is not None:
                    cut("before_commit")
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            if cut is not None:
                cut("after_commit")
            return operation + digest + sequence.to_bytes(8, "big")

    def set_desired(self, principal, anchor, resource, version, payload):
        if (len(principal) != 32 or len(anchor) != 72 or len(resource) != 32
                or not isinstance(version, int) or not 1 <= version < 2**63
                or len(payload) > self.MAX_PAYLOAD):
            raise StoreError("invalid desired state")
        with self.authorize(principal, anchor, resource, "management"):
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT version,payload FROM desired WHERE principal=? AND resource=?", (principal, resource)).fetchone()
                if row is not None and (version < row[0] or (version == row[0] and payload != row[1])):
                    raise StoreError("desired version conflict")
                if row is None:
                    if self.db.execute("SELECT COUNT(*) FROM desired").fetchone()[0] >= self.MAX_ROWS:
                        raise StoreError("desired capacity")
                    self.db.execute("INSERT INTO desired VALUES(?,?,?,?,0)", (principal, resource, version, payload))
                elif version > row[0]:
                    self.db.execute("UPDATE desired SET version=?,payload=? WHERE principal=? AND resource=?", (version, payload, principal, resource))
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def get_desired(self, principal, anchor, resource):
        with self.authorize(principal, anchor, resource, "desired"):
            return self.db.execute("SELECT version,payload FROM desired WHERE principal=? AND resource=?", (principal, resource)).fetchone()

    def report_applied(self, principal, anchor, resource, version):
        with self.authorize(principal, anchor, resource, "applied"):
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute("SELECT version,applied FROM desired WHERE principal=? AND resource=?", (principal, resource)).fetchone()
                if (row is None or not isinstance(version, int)
                        or not row[1] <= version <= row[0]):
                    raise StoreError("invalid applied version")
                self.db.execute("UPDATE desired SET applied=? WHERE principal=? AND resource=?", (version, principal, resource))
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
