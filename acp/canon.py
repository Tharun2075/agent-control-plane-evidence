"""Canonical JSON and SHA-256 helpers.

Canonical form: UTF-8 JSON, keys sorted, no insignificant whitespace, no NaN.
For the value types this project uses (strings, integers, booleans, null,
lists, objects; no floats) this matches the RFC 8785 JSON Canonicalization
Scheme output, so digests can be recomputed by any JCS implementation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """SHA-256 of the canonical JSON form, as 'sha256:<hex>'."""
    return "sha256:" + sha256_hex(canonical(obj))


def file_digest(path) -> str:
    with open(path, "rb") as f:
        return "sha256:" + sha256_hex(f.read())
