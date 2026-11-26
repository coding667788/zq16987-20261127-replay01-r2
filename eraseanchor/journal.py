"""Synthetic append-only transaction images.

No operating-system or real key-store APIs are used.  A journal is JSON Lines
with an optional SHA-256 hash chain.  The journal distinguishes data writes from
metadata commits and records recovery/retry decisions.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .model import CaseError


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


class Journal:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict[str, Any]] = []
        self.torn_tail = False
        if self.path is not None and self.path.exists():
            loaded = read_journal(self.path)
            self.records = loaded["records"]
            self.torn_tail = loaded["torn_tail"]

    @property
    def last_hash(self) -> str:
        return self.records[-1]["hash"] if self.records else ""

    def rewrite_valid_prefix(self) -> None:
        """Truncate a torn final line and rewrite the validated prefix."""

        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8", newline="\n") as fh:
            for rec in self.records:
                fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        rec = dict(record)
        rec["lsn"] = len(self.records) + 1
        rec["prev_hash"] = self.last_hash
        rec["hash"] = record_hash(rec)
        self.records.append(rec)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return rec


def read_journal(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    records: list[dict[str, Any]] = []
    torn_tail = False
    chain_valid = True
    errors: list[str] = []
    if not p.exists():
        return {"records": records, "torn_tail": False, "chain_valid": True, "errors": []}

    lines = p.read_text(encoding="utf-8").splitlines()
    prev = ""
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            torn_tail = True
            errors.append(f"line {lineno}: torn/invalid JSON tail ignored")
            break
        expected_hash = rec.get("hash")
        actual_hash = record_hash(rec)
        if rec.get("prev_hash") != prev or expected_hash != actual_hash:
            chain_valid = False
            errors.append(f"line {lineno}: hash chain mismatch")
            break
        records.append(rec)
        prev = actual_hash
    return {
        "records": records,
        "torn_tail": torn_tail,
        "chain_valid": chain_valid,
        "errors": errors,
    }


def write_fresh_journal(path: str | Path | None, records: list[dict[str, Any]]) -> Journal:
    if path is not None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    journal = Journal(path)
    for rec in records:
        journal.append({k: v for k, v in rec.items() if k not in {"lsn", "hash", "prev_hash"}})
    return journal
