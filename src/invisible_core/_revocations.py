"""The revocation data of a retail Firefox, built by the core from Mozilla's Remote Settings: OneCRL and the CRLite filters.

A retail Firefox 159 keeps two more collections of the bucket `security-state` in cert_storage, next to the intermediates (`_intermediates.py`):
  * `onecrl` (`security/manager/ssl/RemoteSecuritySettings.sys.mjs`, `updateCertBlocklist`, lines 186-233): every record that has an `issuerName` and a
    `serialNumber` becomes an issuer/serial revocation; otherwise, with a `subject` and a `pubKeyHash`, a subject/pubkey revocation; otherwise it is skipped.
    Every one is handed to `setRevocations` as STATE_ENFORCE. The field `enabled` is NOT read (more than half of today's records say `enabled:false` and
    retail applies them all), there is no `filter_expression` and no attachment.
  * `cert-revocations` (the same file, `CRLiteFilters`, lines 583-767): the records go through `_filterEntries`, i.e. the JEXL `filter_expression` of each (a
    record without one is kept); of the kept ones exactly ONE has `incremental: false` (the full filter) and the others are deltas. Each attachment is
    downloaded on its own, from `<attachments base_url><attachment.location>`, and checked: sha256 == `attachment.hash`, length == `attachment.size`.
    There is no zip bundle for this collection. The order of the records is the one of `db.list()`: an IndexedDB `getAll` on the index `cid` with the primary key
    `["_cid","id"]`, i.e. ascending `id`; the deltas are applied in that order.
The engine does not sync them any more (a sync reaches Mozilla from the engine's own process, on a clock nobody declared): the core builds, from the same
service and from the USER's Python, the two inputs the engine reads in its generate mode. This module only BUILDS them; where they are kept and when they are
renewed is the caller's.

THE FILES (read by the engine; the format is its contract and is changed with it), compact, UTF-8, no newline:

    onecrl.json    {"format":1,"collection":"onecrl","collection_timestamp":<int>,"updated_utc":"...Z",
                    "revocations":[{"issuerName":"<b64>","serialNumber":"<b64>"} | {"subject":"<b64>","pubKeyHash":"<b64>"}, ...]}
    crlite.json    {"format":1,"collection":"cert-revocations","channel":"default","collection_timestamp":<int>,"updated_utc":"...Z",
                    "full":{"file":"<name>","sha256":"<hex>","size":<int>},"deltas":[{"file":..,"sha256":..,"size":..}, ...]}
                   beside it, one file per entry, named as in the manifest (the attachment's own `filename`).

The `revocations` are in `id` order (the order retail adds them) and carry only the two fields of their kind; the `deltas` are in retail order.

NOTHING THAT DOES NOT ADD UP IS KEPT, as in `_intermediates.py`: a missing or invalid timestamp, two records with the same id, a value that is not strict
base64, an empty collection, a number of full filters other than one, two attachments with the same hash or the same name, a name that is not a plain
basename, a sha256 or a size that is not the record's: each refuses the whole download with `RevocationsError` and the caller's cache stays as it was. A
`filter_expression` that is not one of the two forms Mozilla publishes today is refused too (never guessed): an unknown expression could mean a record
retail would drop or one it would keep, and the only safe answer is to keep the old data until the parser is taught the new form.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from . import _intermediates as _im
from . import download
from .constants import (
    CRLITE_CHANNEL,
    CRLITE_FILE_NAME,
    FIREFOX_UPSTREAM_VERSION,
    ONECRL_FILE_NAME,
    SECURITY_STATE_CHANGESET_URL_TEMPLATE,
)

__all__ = [
    "RevocationsError",
    "fetch_changeset",
    "version_compare",
    "filter_expression_holds",
    "build_onecrl",
    "crlite_records",
    "fetch_crlite",
    "write_onecrl",
]


class RevocationsError(_im.IntermediatesError):
    """What was downloaded does not add up, or cannot be used. The same family as `IntermediatesError`: the callers that catch one catch both."""


# --- the changeset -----------------------------------------------------------------------------------------------------------------------------------

def fetch_changeset(collection: str, expected: int, attempts: int) -> dict:
    """The changeset of one collection of the bucket (`expected` = its timestamp from the changes feed, or 0), through the module's one network seam."""
    url = SECURITY_STATE_CHANGESET_URL_TEMPLATE.format(collection=collection, expected=expected)
    changeset = _im._get_json(url, attempts)
    if not isinstance(changeset, dict):
        raise RevocationsError("the changeset of %s is not an object" % collection)
    return changeset


def _timestamp_and_records(changeset: dict, what: str) -> Tuple[int, List[dict]]:
    """The changeset's timestamp and its records without the deleted ones (the way `_intermediates.build_list` reads it), in `id` order."""
    timestamp = changeset.get("timestamp") if isinstance(changeset, dict) else None
    records = changeset.get("changes") if isinstance(changeset, dict) else None
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp <= 0 or not isinstance(records, list):
        raise RevocationsError("the changeset of %s has no timestamp or no records" % what)
    records = [r for r in records if isinstance(r, dict) and not r.get("deleted")]
    if not records:
        raise RevocationsError("the collection %s has no records" % what)
    ids = [r.get("id") for r in records]
    if not all(isinstance(i, str) and i for i in ids):
        raise RevocationsError("a record of %s has no id" % what)
    if len(set(ids)) != len(ids):
        raise RevocationsError("two records of %s have the same id" % what)
    return timestamp, sorted(records, key=lambda r: r["id"])


_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _checked_utc(updated_utc: str) -> str:
    if not isinstance(updated_utc, str) or _UTC.fullmatch(updated_utc) is None:
        raise RevocationsError("updated_utc is not a UTC time like 2026-01-31T12:00:00Z: %r" % (updated_utc,))
    return updated_utc


# --- nsVersionComparator.cpp, ported (the `versionCompare` of the JEXL filters is `Services.vc.compare`) -----------------------------------------------

_INT32_MAX = 2147483647


def _strtol(text: bytes) -> Tuple[int, int]:
    """C `strtol(text, &end, 10)` as `ns_strtol` uses it: (the value, the index where the number ends). No digits: (0, 0); an out of range number: 0."""
    i = 0
    while i < len(text) and text[i] in b" \t\n\v\f\r":
        i += 1
    sign = 1
    if i < len(text) and text[i] in b"+-":
        sign = -1 if text[i] == 0x2D else 1
        i += 1
    digits = i
    while i < len(text) and 0x30 <= text[i] <= 0x39:
        i += 1
    if i == digits:
        return 0, 0
    value = sign * int(text[digits:i])
    if value < -_INT32_MAX - 1 or value > _INT32_MAX:  # ERANGE of a long, or outside int32: ns_strtol answers 0
        return 0, i
    return value, i


class _Part:
    __slots__ = ("num_a", "str_b", "num_c", "extra_d")

    def __init__(self) -> None:
        self.num_a = 0
        self.str_b: Optional[bytes] = None     # `strB` with its `strBlen` already applied; None is the null pointer
        self.num_c = 0
        self.extra_d: Optional[bytes] = None


def _parse_part(text: Optional[bytes]) -> Tuple[_Part, Optional[bytes]]:
    """`ParseVP`: one part (up to the next '.') as numA strB numC extraD, and the rest of the string (None when there is none)."""
    part = _Part()
    if text is None:
        return part, None
    dot = text.find(b".")
    rest: Optional[bytes] = None
    if dot >= 0:
        rest = text[dot + 1:]
        text = text[:dot]
        if not rest:
            rest = None
    if text == b"*":
        part.num_a = _INT32_MAX
        tail = b""
    else:
        part.num_a, end = _strtol(text)
        tail = text[end:]
    if tail:
        if tail[0] == 0x2B:  # '+': one more than the number, and the string "pre"
            part.num_a += 1
            part.str_b = b"pre"
        else:
            cut = -1
            for index, byte in enumerate(tail):
                if byte in b"0123456789+-":
                    cut = index
                    break
            if cut < 0:
                part.str_b = tail
            else:
                part.str_b = tail[:cut]
                part.num_c, end = _strtol(tail[cut:])
                extra = tail[cut:][end:]
                part.extra_d = extra or None
    return part, rest


def _cmp(a: int, b: int) -> int:
    return -1 if a < b else (0 if a == b else 1)


def _cmp_str_b(a: Optional[bytes], b: Optional[bytes]) -> int:
    """`ns_strnncmp`: the char is signed, and a missing string is AFTER a present one (so `1.0` is after `1.0a`, a pre-release)."""
    if a is None:
        return 1 if b is not None else 0
    if b is None:
        return -1
    for x, y in zip(a, b):
        x = x - 256 if x > 127 else x
        y = y - 256 if y > 127 else y
        if x < y:
            return -1
        if x > y:
            return 1
    if len(a) == len(b):
        return 0
    return -1 if len(a) < len(b) else 1


def _cmp_extra_d(a: Optional[bytes], b: Optional[bytes]) -> int:
    """`ns_strcmp`: a missing string is after a present one; otherwise `strcmp`."""
    if a is None:
        return 1 if b is not None else 0
    if b is None:
        return -1
    return 0 if a == b else (-1 if a < b else 1)


def version_compare(a: str, b: str) -> int:
    """`Services.vc.compare(a, b)` (xpcom/base/nsVersionComparator.cpp, the `char` version): -1, 0 or 1. Parts are split on '.', each is numA strB numC extraD."""
    rest_a: Optional[bytes] = a.encode("utf-8")
    rest_b: Optional[bytes] = b.encode("utf-8")
    while True:
        pa, rest_a = _parse_part(rest_a)
        pb, rest_b = _parse_part(rest_b)
        result = (_cmp(pa.num_a, pb.num_a) or _cmp_str_b(pa.str_b, pb.str_b) or _cmp(pa.num_c, pb.num_c)
                  or _cmp_extra_d(pa.extra_d, pb.extra_d))
        if result:
            return result
        if rest_a is None and rest_b is None:
            return 0


# --- the filter expressions of the CRLite records ----------------------------------------------------------------------------------------------------

_EXPRESSION = re.compile(
    r"env\.version\|versionCompare\('(?P<version>[^'\\]*)'\) >= 0"
    r" && '(?P<channel>[^'\\]*)' == 'security\.pki\.crlite_channel'\|preferenceValue\('none'\)"
)


def filter_expression_holds(expr: Optional[str], *, version: str, channel: str) -> bool:
    """Does the record's JEXL `filter_expression` hold for this Firefox `version` and this CRLite `channel`?

    Only the form Mozilla publishes is understood, strictly (whitespace included):
    `env.version|versionCompare('V') >= 0 && 'C' == 'security.pki.crlite_channel'|preferenceValue('none')`. No expression (None, or empty as in JS) holds,
    as in `filterEntry`. Anything else raises `RevocationsError`: guessing could keep or drop a record retail does not."""
    if expr is None or expr == "":
        return True
    if not isinstance(expr, str):
        raise RevocationsError("a filter_expression is not a string: %r" % (expr,))
    m = _EXPRESSION.fullmatch(expr)
    if m is None:
        raise RevocationsError("a filter_expression this core does not know how to read: %r" % (expr,))
    return version_compare(version, m.group("version")) >= 0 and m.group("channel") == channel


# --- OneCRL ----------------------------------------------------------------------------------------------------------------------------------------------

def _strict_b64(value, what: str, rid) -> str:
    if not isinstance(value, str):
        raise RevocationsError("record %s: %s is not a string" % (rid, what))
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RevocationsError("record %s: %s is not base64" % (rid, what)) from exc
    return value


def build_onecrl(changeset: dict, *, updated_utc: str) -> dict:
    """The content of `onecrl.json`, or `RevocationsError`. The records are read as `updateCertBlocklist` reads them: issuer and serial first, else subject and
    public key hash, else nothing; `enabled` is not looked at."""
    updated_utc = _checked_utc(updated_utc)
    timestamp, records = _timestamp_and_records(changeset, "onecrl")
    revocations = []
    for r in records:
        rid = r["id"]
        if r.get("issuerName") and r.get("serialNumber"):
            revocations.append({
                "issuerName": _strict_b64(r["issuerName"], "issuerName", rid),
                "serialNumber": _strict_b64(r["serialNumber"], "serialNumber", rid),
            })
        elif r.get("subject") and r.get("pubKeyHash"):
            revocations.append({
                "subject": _strict_b64(r["subject"], "subject", rid),
                "pubKeyHash": _strict_b64(r["pubKeyHash"], "pubKeyHash", rid),
            })
    return {
        "format": 1,
        "collection": "onecrl",
        "collection_timestamp": timestamp,
        "updated_utc": updated_utc,
        "revocations": revocations,
    }


def write_onecrl(directory: Path, listing: dict) -> Path:
    """`onecrl.json` in `directory`, compact."""
    path = Path(directory) / ONECRL_FILE_NAME
    path.write_bytes(_im._compact(listing))
    return path


# --- CRLite ----------------------------------------------------------------------------------------------------------------------------------------------

_HEX64 = re.compile(r"[0-9a-fA-F]{64}")
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")
_DEVICE_NAMES = frozenset({"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
                           "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"})


#: The name the engine's generate mode gives the full CRLite filter in `security_state/` (`_security_state_generate.CRLITE_FILTER_FILE_NAME`): an attachment of this name (full or
#: delta, any case) would be a second file the launch could take for the engine's own, or be taken for one when the filters are left out of a stale profile.
ENGINE_FILTER_NAME = "crlite.filter"


def _safe_basename(name) -> bool:
    """A plain file name: no separator, no `..`, no drive letter, no empty name, nothing Windows would reinterpret."""
    if not isinstance(name, str) or _SAFE_NAME.fullmatch(name) is None or ".." in name:
        return False
    if name.endswith("."):
        return False
    return name.split(".")[0].lower() not in _DEVICE_NAMES


def _attachment_of(record: dict) -> dict:
    rid = record.get("id")
    attachment = record.get("attachment")
    if not isinstance(attachment, dict):
        raise RevocationsError("record %s: no attachment" % rid)
    name = attachment.get("filename")
    if not _safe_basename(name):
        raise RevocationsError("record %s: the attachment's filename is not a plain file name: %r" % (rid, name))
    if name.lower() == CRLITE_FILE_NAME:
        raise RevocationsError("record %s: the attachment's filename is the manifest's" % rid)
    if name.lower() == ENGINE_FILTER_NAME:
        raise RevocationsError("record %s: the attachment's filename is the one the engine writes the full filter under in security_state" % rid)
    digest = attachment.get("hash")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise RevocationsError("record %s: the attachment has no sha256" % rid)
    size = attachment.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or size > _im._MAX_BODY:
        raise RevocationsError("record %s: the attachment has no usable size: %r" % (rid, size))
    location = attachment.get("location")
    if (not isinstance(location, str) or not location or location.startswith("/") or "\\" in location
            or any(c.isspace() or ord(c) < 32 for c in location)):
        raise RevocationsError("record %s: the attachment has no usable location: %r" % (rid, location))
    return attachment


def crlite_records(changeset: dict, *, version: str = FIREFOX_UPSTREAM_VERSION,
                   channel: str = CRLITE_CHANNEL) -> Tuple[dict, List[dict]]:
    """`(the full filter's record, the delta records in the order retail applies them)`, or `RevocationsError`. The records are those whose expression holds for
    `version` and `channel`; exactly one is full (`incremental: false`)."""
    _timestamp, records = _timestamp_and_records(changeset, "cert-revocations")
    kept = [r for r in records if filter_expression_holds(r.get("filter_expression"), version=version, channel=channel)]
    full = []
    deltas = []
    for r in kept:
        flag = r.get("incremental")
        if not isinstance(flag, bool):
            raise RevocationsError("record %s: `incremental` is not true or false" % r["id"])
        _attachment_of(r)
        (deltas if flag else full).append(r)
    if len(full) != 1:
        raise RevocationsError("%d full filters for this channel, not one" % len(full))
    chosen = full + deltas
    hashes = [r["attachment"]["hash"].lower() for r in chosen]
    if len(set(hashes)) != len(hashes):
        raise RevocationsError("two records have the same attachment")
    names = [r["attachment"]["filename"].lower() for r in chosen]
    if len(set(names)) != len(names):
        raise RevocationsError("two records have the same filename")
    return full[0], deltas


def _entry(record: dict) -> dict:
    a = record["attachment"]
    return {"file": a["filename"], "sha256": a["hash"].lower(), "size": a["size"]}


def _check(raw: bytes, entry: dict, rid) -> None:
    if len(raw) != entry["size"]:
        raise RevocationsError("record %s: the attachment is %d bytes, the record says %d" % (rid, len(raw), entry["size"]))
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise RevocationsError("record %s: the sha256 of the attachment is not the record's" % rid)


def fetch_crlite(directory: Path, changeset: dict, base: str, *, reuse: Callable[[str], Optional[Path]], attempts: int,
                 updated_utc: str) -> dict:
    """Put the filters in `directory` and write `crlite.json` after them; the manifest. Raises on anything that does not add up (the caller works in a
    staging directory, so nothing is cleaned up here).

    Each attachment is `directory/<its filename>`. `reuse(sha256_hex)` may name a file the caller already holds with that hash: it is COPIED (never linked)
    and verified again, and the network is not asked for it. A held file that fails the check (size or sha256) is IGNORED, not refused: a corrupted file in
    the caller's cache must not block every later fetch, so the attachment is downloaded from `base + location` as if nothing were held, and the
    downloaded bytes must pass the same check or the download is refused. The held file is never modified."""
    updated_utc = _checked_utc(updated_utc)
    timestamp, _records = _timestamp_and_records(changeset, "cert-revocations")
    full, deltas = crlite_records(changeset)
    directory = Path(directory)
    for record in [full] + deltas:
        entry = _entry(record)
        rid = record["id"]
        held = reuse(entry["sha256"])
        raw = None
        if held is not None:
            try:
                candidate = Path(held).read_bytes()
            except OSError:
                candidate = None
            if candidate is not None and len(candidate) == entry["size"] and hashlib.sha256(candidate).hexdigest() == entry["sha256"]:
                raw = candidate
        if raw is None:
            url = base + record["attachment"]["location"]
            raw = download._with_retries(lambda: _im._get(url), "the CRLite filter %s" % entry["file"], attempts)
        _check(raw, entry, rid)
        (directory / entry["file"]).write_bytes(raw)
    manifest = {
        "format": 1,
        "collection": "cert-revocations",
        "channel": CRLITE_CHANNEL,
        "collection_timestamp": timestamp,
        "updated_utc": updated_utc,
        "full": _entry(full),
        "deltas": [_entry(r) for r in deltas],
    }
    (directory / CRLITE_FILE_NAME).write_bytes(_im._compact(manifest))
    return manifest
