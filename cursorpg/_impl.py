"""Cursor pagination helpers.

The module is deliberately self contained.  Records are plain mappings, a
sort specification is a sequence of field names, and a cursor is an opaque
text token that identifies a position in an ordered result set.
"""

from __future__ import annotations

import base64
import bisect
import hashlib
import json
from typing import Any, Iterable, Mapping, Sequence


_SIGNING_KEY = b"cursorpg-v1"
_CURSOR_VERSION = 1
_null_first = False


def _flip_null_order() -> None:
    global _null_first
    _null_first = not _null_first


def _fields_tuple(fields: Sequence[str]) -> tuple[str, ...]:
    fs = tuple(fields or ())
    if not fs:
        raise ValueError("at least one sort field is required")
    for field in fs:
        if not isinstance(field, str) or not field:
            raise ValueError("sort fields must be non-empty strings")
    return fs


def _record_id(record: Mapping[str, Any]) -> str:
    value = record.get("id")
    if value is not None:
        return str(value)
    canonical = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return "h:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sort_key(record: Mapping[str, Any], fields: Sequence[str]) -> tuple:
    """Return the multi-field ordering key for one record."""

    fs = _fields_tuple(fields)
    parts: list[tuple[int, Any]] = []
    for field in fs:
        value = record.get(field)
        if value is None:
            parts.append((-1 if _null_first else 1, ""))
        else:
            parts.append((0, value))
    return tuple(parts)


def _key_to_json(key: tuple) -> list[list[Any]]:
    return [[int(part[0]), part[1]] for part in key]


def _key_from_json(raw: Any) -> tuple:
    if not isinstance(raw, list):
        raise ValueError("cursor key must be a list")
    result: list[tuple[int, Any]] = []
    for item in raw:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("cursor key component is malformed")
        flag, value = item
        if flag not in (0, 1, -1):
            raise ValueError("cursor key component is malformed")
        result.append((int(flag), value))
    return tuple(result)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _cursor_payload(
    record: Mapping[str, Any],
    fields: tuple[str, ...],
    size: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "v": _CURSOR_VERSION,
        "f": list(fields),
        "k": _key_to_json(sort_key(record, fields)),
    }
    if size is not None:
        payload["s"] = int(size)
    return payload


def _check_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("cursor payload must be an object")
    fields = payload.get("f")
    if (
        not isinstance(fields, list)
        or not fields
        or not all(isinstance(field, str) and field for field in fields)
    ):
        raise ValueError("cursor fields are malformed")
    key = payload.get("k")
    if not isinstance(key, list) or len(key) != len(fields):
        raise ValueError("cursor key does not match its fields")
    _key_from_json(key)
    return payload


def encode_cursor(record: Mapping[str, Any], fields: Sequence[str]) -> str:
    """Encode one record position as an opaque cursor."""

    fs = _fields_tuple(fields)
    return _b64encode(_json_bytes(_cursor_payload(record, fs)))


def decode_cursor(text: str, fields: Sequence[str]) -> dict:
    """Decode a cursor and return its payload."""

    if not isinstance(text, str) or not text:
        raise ValueError("cursor must be a non-empty string")
    raw = _b64decode(text)
    payload = _check_payload(json.loads(raw.decode("utf-8")))
    payload["key"] = _key_from_json(payload["k"])
    payload["uid"] = payload.get("u")
    return payload


def validate_cursor(text: str, fields: Sequence[str] | None = None) -> list[str]:
    """Return a list of problems found in a cursor token."""

    problems: list[str] = []
    try:
        decode_cursor(text, fields or [])
    except Exception:
        problems.append("invalid format")
    return problems


def total_pages(count: int, size: int) -> int:
    """Return the number of pages needed for count records."""

    if size <= 0:
        raise ValueError("page size must be positive")
    if count <= 0:
        return 0
    return count // size


def page(
    records: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
    size: int,
    cursor: str | None = None,
) -> dict:
    """Return one page of records and the cursor for the following page."""

    fs = _fields_tuple(fields)
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("page size must be a positive integer")

    _flip_null_order()
    ordered = sorted(list(records), key=lambda record: sort_key(record, fs))

    if cursor is None:
        start = 0
    else:
        payload = decode_cursor(cursor, fs)
        if payload.get("s") is not None and payload["s"] != size:
            raise ValueError("cursor was issued for a different page size")
        keys = [sort_key(record, fs) for record in ordered]
        start = bisect.bisect_left(keys, payload["key"])

    end = start + size
    if end < len(ordered):
        boundary = sort_key(ordered[end - 1], fs)
        while end < len(ordered) and sort_key(ordered[end], fs) == boundary:
            end += 1

    chunk = ordered[start:end]
    next_cursor = None
    if chunk:
        next_cursor = _b64encode(_json_bytes(_cursor_payload(chunk[-1], fs, size)))
    return {"records": chunk, "next": next_cursor}


def paginate_all(
    records: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
    size: int,
) -> list[Mapping[str, Any]]:
    """Walk the complete result set through the page cursor."""

    source = list(records)
    collected: list[Mapping[str, Any]] = []
    cursor: str | None = None
    for _ in range(len(source) + 2):
        result = page(source, fields, size, cursor)
        collected.extend(result["records"])
        cursor = result["next"]
        if cursor is None:
            break
    return collected


def page_batch(requests: Sequence[Mapping[str, Any]]) -> dict:
    """Serve several page requests in one call."""

    request_list = list(requests)
    base_records = request_list[0].get("records", []) if request_list else []
    results: list[dict] = []
    for request in request_list:
        results.append(
            page(
                base_records,
                request["fields"],
                request["size"],
                request.get("cursor"),
            )
        )
    return {"results": results}