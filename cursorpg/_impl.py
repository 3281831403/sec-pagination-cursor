"""Cursor pagination helpers.

The module is deliberately self contained.  Records are plain mappings, a
sort specification is a sequence of field names, and a cursor is an opaque
text token that identifies a position in an ordered result set.

A cursor is *signed* with an HMAC and only ever names one concrete record
(its ordering key plus its record id).  When the record set is associated
with a tenant, the tenant is carried inside the signed payload as well, so a
cursor issued for one tenant cannot be replayed against another tenant's
data even if the attacker can obtain a legitimately signed token elsewhere.
"""

from __future__ import annotations

import base64
import bisect
import hashlib
import hmac
import json
from typing import Any, Iterable, Mapping, Sequence


_SIGNING_KEY = b"cursorpg-v1-signing-key"
_CURSOR_VERSION = 1

# Field names that are treated as the tenant/owner of a record when the
# caller does not pass an explicit tenant.  The list is intentionally narrow:
# a value is only used for cross-checking when the whole record set agrees on
# it.
_TENANT_FIELDS = (
    "tenant",
    "tenant_id",
    "tenantId",
    "org",
    "org_id",
    "orgId",
    "organization",
    "organization_id",
    "organizationId",
    "account",
    "account_id",
    "accountId",
    "customer",
    "customer_id",
    "customerId",
    "workspace",
    "workspace_id",
    "workspaceId",
    "project_id",
    "projectId",
    "team_id",
    "teamId",
    "owner_id",
    "ownerId",
)


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


def _record_tenant(record: Mapping[str, Any]) -> str | None:
    """Return the tenant a record belongs to, if it declares one."""

    for field in _TENANT_FIELDS:
        value = record.get(field)
        if value is not None:
            return str(value)
    return None


def sort_key(record: Mapping[str, Any], fields: Sequence[str]) -> tuple:
    """Return the multi-field ordering key for one record.

    Values sort in ascending order and ``None`` always sorts last.  The key
    is not by itself unique: callers that need a total order append the
    record id (see :func:`page`).
    """

    fs = _fields_tuple(fields)
    parts: list[tuple[int, Any]] = []
    for field in fs:
        value = record.get(field)
        if value is None:
            parts.append((1, ""))
        else:
            parts.append((0, value))
    return tuple(parts)


def _json_safe(value: Any) -> Any:
    """Round-trip a value through JSON so both sides of a comparison agree."""

    return json.loads(
        json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    )


def _cmp_part(part: tuple) -> tuple:
    """Map one ordering component to a totally comparable, JSON-stable tuple."""

    flag, value = part
    if flag:
        return (1, 0, "")
    safe = _json_safe(value)
    if isinstance(safe, bool):
        return (0, 1, int(safe))
    if isinstance(safe, (int, float)):
        return (0, 1, safe)
    if isinstance(safe, str):
        return (0, 2, safe)
    return (
        0,
        3,
        json.dumps(
            safe,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ),
    )


def _cmp_key(key: tuple) -> tuple:
    return tuple(_cmp_part(part) for part in key)


def _full_key(record: Mapping[str, Any], fields: tuple[str, ...]) -> tuple:
    """Total ordering key: sort fields followed by the unique record id."""

    return _cmp_key(sort_key(record, fields)) + (_record_id(record),)


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
        if flag not in (0, 1) or isinstance(flag, bool):
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
        default=str,
    ).encode("utf-8")


def _sign_payload(payload: Mapping[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "sig"}
    return hmac.new(_SIGNING_KEY, _json_bytes(body), hashlib.sha256).hexdigest()


def _cursor_payload(
    record: Mapping[str, Any],
    fields: tuple[str, ...],
    size: int | None = None,
    tenant: str | None = None,
) -> dict[str, Any]:
    resolved_tenant = tenant if tenant is not None else _record_tenant(record)
    payload: dict[str, Any] = {
        "v": _CURSOR_VERSION,
        "f": list(fields),
        "k": _key_to_json(sort_key(record, fields)),
        "i": _record_id(record),
    }
    if resolved_tenant is not None:
        payload["u"] = str(resolved_tenant)
    if size is not None:
        payload["s"] = int(size)
    return payload


def _check_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("cursor payload must be an object")
    if payload.get("v") != _CURSOR_VERSION:
        raise ValueError("unsupported cursor version")
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
    record_id = payload.get("i")
    if not isinstance(record_id, str) or not record_id:
        raise ValueError("cursor does not identify a record")
    tenant = payload.get("u")
    if tenant is not None and not isinstance(tenant, str):
        raise ValueError("cursor tenant is malformed")
    size = payload.get("s")
    if size is not None and (
        not isinstance(size, int) or isinstance(size, bool) or size <= 0
    ):
        raise ValueError("cursor page size is malformed")
    return payload


def encode_cursor(
    record: Mapping[str, Any],
    fields: Sequence[str],
    tenant: str | None = None,
) -> str:
    """Encode one record position as an opaque, signed cursor."""

    fs = _fields_tuple(fields)
    payload = _cursor_payload(record, fs, tenant=tenant)
    payload["sig"] = _sign_payload(payload)
    return _b64encode(_json_bytes(payload))


def decode_cursor(text: str, fields: Sequence[str] | None = None) -> dict:
    """Decode a signed cursor and return its payload.

    Raises :class:`ValueError` for malformed tokens, for tokens whose
    signature does not verify (i.e. tampered cursors), and for tokens issued
    for a different sort specification than the one requested.
    """

    if not isinstance(text, str) or not text:
        raise ValueError("cursor must be a non-empty string")
    try:
        raw = _b64decode(text)
    except Exception as exc:  # noqa: BLE001 - normalise to ValueError
        raise ValueError("cursor is not valid base64") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - normalise to ValueError
        raise ValueError("cursor is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("cursor payload must be an object")

    signature = payload.get("sig")
    if not isinstance(signature, str) or not signature:
        raise ValueError("cursor signature is missing")
    if not hmac.compare_digest(signature, _sign_payload(payload)):
        raise ValueError("cursor signature is invalid")

    _check_payload(payload)

    expected_fields = tuple(fields) if fields else ()
    if expected_fields and tuple(payload["f"]) != expected_fields:
        raise ValueError("cursor was issued for different sort fields")

    payload["key"] = _key_from_json(payload["k"])
    payload["id"] = payload["i"]
    payload["uid"] = payload.get("u")
    return payload


def validate_cursor(text: str, fields: Sequence[str] | None = None) -> list[str]:
    """Return a list of problems found in a cursor token (empty when valid)."""

    problems: list[str] = []
    try:
        decode_cursor(text, fields)
    except Exception:
        problems.append("invalid format")
    return problems


def total_pages(count: int, size: int) -> int:
    """Return the number of pages needed for count records."""

    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("page size must be positive")
    if count <= 0:
        return 0
    return (int(count) + size - 1) // size


def _expected_tenant(
    records: Sequence[Mapping[str, Any]], tenant: str | None
) -> str | None:
    """Resolve the tenant a cursor must belong to for this record set."""

    if tenant is not None:
        return str(tenant)
    values = {
        value
        for value in (_record_tenant(record) for record in records)
        if value is not None
    }
    if len(values) == 1:
        return next(iter(values))
    return None


def page(
    records: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
    size: int,
    cursor: str | None = None,
    tenant: str | None = None,
) -> dict:
    """Return one page of records and the cursor for the following page.

    The cursor identifies one record; the returned page begins strictly
    after it.  A cursor that has been tampered with, or that was issued for a
    different tenant or sort specification, is rejected with ``ValueError``.
    """

    fs = _fields_tuple(fields)
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError("page size must be a positive integer")

    source = list(records)
    ordered = sorted(source, key=lambda record: _full_key(record, fs))
    ordered_keys = [_full_key(record, fs) for record in ordered]
    wanted_tenant = _expected_tenant(source, tenant)

    if cursor is None:
        start = 0
    else:
        payload = decode_cursor(cursor, fs)
        cursor_tenant = payload.get("u")
        if wanted_tenant is not None and cursor_tenant != wanted_tenant:
            raise ValueError("cursor does not belong to this tenant")
        position = _cmp_key(payload["key"]) + (payload["id"],)
        start = bisect.bisect_right(ordered_keys, position)

    end = start + size
    chunk = ordered[start:end]

    next_cursor = None
    if chunk and end < len(ordered):
        last = chunk[-1]
        next_cursor = _b64encode(
            _json_bytes(
                _signed_payload(last, fs, size, wanted_tenant)
            )
        )
    return {"records": chunk, "next": next_cursor}


def _signed_payload(
    record: Mapping[str, Any],
    fields: tuple[str, ...],
    size: int,
    tenant: str | None,
) -> dict[str, Any]:
    payload = _cursor_payload(record, fields, size, tenant)
    payload["sig"] = _sign_payload(payload)
    return payload


def paginate_all(
    records: Iterable[Mapping[str, Any]],
    fields: Sequence[str],
    size: int,
) -> list[Mapping[str, Any]]:
    """Walk the complete result set through the page cursor."""

    source = list(records)
    collected: list[Mapping[str, Any]] = []
    cursor: str | None = None
    seen: set[str] = set()
    # Every non-final page advances by at least one record, so one extra
    # iteration over the record count is always enough.
    for _ in range(len(source) + 2):
        result = page(source, fields, size, cursor)
        collected.extend(result["records"])
        cursor = result["next"]
        if cursor is None:
            break
        if cursor in seen:  # pragma: no cover - defensive against cycles
            break
        seen.add(cursor)
    return collected


def page_batch(requests: Sequence[Mapping[str, Any]]) -> dict:
    """Serve several page requests in one call.

    Each request is independent: it carries its own record set, sort
    specification, page size and cursor.
    """

    results: list[dict] = []
    for request in requests:
        results.append(
            page(
                request.get("records", []),
                request["fields"],
                request["size"],
                request.get("cursor"),
                request.get("tenant"),
            )
        )
    return {"results": results}
