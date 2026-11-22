"""The preloaded intermediate certificates, downloaded and verified by the core: one of the three inputs of the engine's generate mode.

A retail Firefox has the intermediates of the public web in `cert_storage` from its first second: it takes them from Mozilla's Remote Settings collection
`security-state/intermediates`. The engine does not sync that collection any more (a sync reaches Mozilla's servers from the engine's own process, on a clock
nobody declared), so the core downloads it from the same service Firefox uses, from the USER's Python, and verifies it. This module only BUILDS the input; where
it is kept, when it is renewed and how it reaches a profile is `_security_state.py`'s (the one road of the security state: the intermediates, OneCRL and the
CRLite filters, handed together to the engine's generate mode, whose result every launch copies into its profile).

THE FILE (read by the engine; its format is the engine's contract and is changed with it):

    {"format":1,"collection":"security-state/intermediates","collection_timestamp":<int>,"fetched_utc":"...Z","count":N,
     "set_sha256":"<hex sha256 of the derHashes, sorted, joined by \\n>",
     "certs":[{"derHash":"<b64>","cert":"<b64 DER>","subject":"<b64 DER of the subject>"}]}

compact, UTF-8, LF, the certs sorted by derHash.

NOTHING THAT DOES NOT ADD UP IS KEPT. Every record is checked against what the server itself says about it (the sha256 of the attachment, the hash of the
DER, the subject) and the number of certificates against the number of records; one piece that fails refuses the whole download (`IntermediatesError`) and the
caller's cache stays as it was. The checks use only the standard library (a minimal DER reader for the subject, below): a certificate library would be a
dependency for one field.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

from .constants import (
    INTERMEDIATES_BUNDLE_PATH,
    INTERMEDIATES_COLLECTION_ID,
    INTERMEDIATES_FILE_NAME,
    INTERMEDIATES_SERVER_INFO_URL,
    SECURITY_STATE_CHANGESET_URL_TEMPLATE,
)
from .download import _with_retries

__all__ = ["IntermediatesError", "fetch_intermediates"]

#: The collection's name as the file says it.
_COLLECTION = "security-state/intermediates"

#: Bounds on what a server may hand back: the whole bundle, one attachment, one JSON answer. A certificate is about 2 KB and the bundle about 4 MB; the
#: bounds only stop a wrong answer from filling memory.
_MAX_BODY = 64 << 20
_MAX_ATTACHMENT = 1 << 20


class IntermediatesError(RuntimeError):
    """What was downloaded does not add up, or cannot be used. Never retried: asking again returns the same bytes."""


# --- the network (ONE seam) --------------------------------------------------------------------------------------------------------------------------

def _get(url: str) -> bytes:
    """The bytes of `url`. The only function of this module (and of `_revocations`, which uses it) that reaches the network: a failure is a `requests` exception, so `_with_retries` reads its
    status the way it does for the other downloads."""
    with requests.get(url, timeout=(10, 60), stream=True) as r:
        r.raise_for_status()
        body = bytearray()
        for chunk in r.iter_content(1 << 16):
            body += chunk
            if len(body) > _MAX_BODY:
                raise IntermediatesError("the answer of %s is larger than %d bytes" % (url, _MAX_BODY))
        return bytes(body)


def _get_json(url: str, attempts: int):
    raw = _with_retries(lambda: _get(url), "the intermediates list", attempts)
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise IntermediatesError("the answer of %s is not JSON: %s" % (url, exc)) from exc


# --- reading a certificate (the subject), without a library -------------------------------------------------------------------------------------------

def _tlv(buf: bytes, pos: int):
    """(tag, start of the content, end of the element) of the DER element at `pos`; a truncated or oversized element raises."""
    if pos + 2 > len(buf):
        raise IntermediatesError("DER ends inside an element")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise IntermediatesError("DER tag of more than one byte")
    first = buf[pos + 1]
    if first < 0x80:
        start, length = pos + 2, first
    else:
        count = first & 0x7F
        if count == 0 or count > 4 or pos + 2 + count > len(buf):
            raise IntermediatesError("DER length is not a definite length")
        start = pos + 2 + count
        length = int.from_bytes(buf[pos + 2:start], "big")
    end = start + length
    if end > len(buf):
        raise IntermediatesError("DER element runs past the end")
    return tag, start, end


def subject_der(cert: bytes) -> bytes:
    """The DER of the certificate's subject (the whole SEQUENCE, tag and length included).

    Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version OPTIONAL, serialNumber, signature, issuer, validity, subject, ... }, ... }"""
    tag, start, end = _tlv(cert, 0)
    if tag != 0x30 or end != len(cert):
        raise IntermediatesError("not a DER certificate")
    tag, pos, tbs_end = _tlv(cert, start)
    if tag != 0x30:
        raise IntermediatesError("no tbsCertificate")
    tag, _s, e = _tlv(cert, pos)
    if tag == 0xA0:  # the explicit version
        pos = e
    for expected in (0x02, 0x30, 0x30, 0x30):  # serialNumber, signature, issuer, validity
        tag, _s, e = _tlv(cert, pos)
        if tag != expected:
            raise IntermediatesError("tbsCertificate is not laid out as RFC 5280 says")
        pos = e
    tag, _s, e = _tlv(cert, pos)
    if tag != 0x30 or e > tbs_end:
        raise IntermediatesError("no subject in tbsCertificate")
    return cert[pos:e]


_PEM = re.compile(r"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----", re.S)


def _pem_to_der(raw: bytes) -> bytes:
    """The DER of a PEM that holds exactly one certificate and nothing else."""
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise IntermediatesError("the attachment is not ASCII PEM") from exc
    m = _PEM.fullmatch(text)
    if m is None:
        raise IntermediatesError("the attachment is not one PEM certificate")
    try:
        return base64.b64decode("".join(m.group(1).split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntermediatesError("the PEM body is not base64") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- verifying a download ----------------------------------------------------------------------------------------------------------------------------

def _verified_cert(record: dict, raw: bytes) -> dict:
    """The entry of the file for one record, or `IntermediatesError`: the sha256 of the attachment is the record's, the DER hashes to its `derHash`, and the
    subject is the record's `subjectDN` when it has one (the older records carry only the hash of the certificate, and then the subject is the
    certificate's own)."""
    rid = record.get("id")
    attachment = record.get("attachment") or {}
    want_hash = attachment.get("hash")
    if not isinstance(want_hash, str) or hashlib.sha256(raw).hexdigest() != want_hash.lower():
        raise IntermediatesError("record %s: the sha256 of the attachment is not the record's" % rid)
    size = attachment.get("size")
    if size is not None and size != len(raw):
        raise IntermediatesError("record %s: the attachment is %d bytes, the record says %r" % (rid, len(raw), size))
    der = _pem_to_der(raw)
    der_hash = _b64(hashlib.sha256(der).digest())
    if record.get("derHash") != der_hash:
        raise IntermediatesError("record %s: the hash of the DER is not the record's derHash" % rid)
    subject = subject_der(der)
    if "subjectDN" in record:
        try:
            declared = base64.b64decode(record["subjectDN"], validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise IntermediatesError("record %s: subjectDN is not base64" % rid) from exc
        if declared != subject:
            raise IntermediatesError("record %s: the subject of the certificate is not the record's subjectDN" % rid)
    return {"derHash": der_hash, "cert": _b64(der), "subject": _b64(subject)}


def _attachments_base(attempts: int) -> str:
    info = _get_json(INTERMEDIATES_SERVER_INFO_URL, attempts)
    try:
        base = info["capabilities"]["attachments"]["base_url"]
    except (KeyError, TypeError) as exc:
        raise IntermediatesError("the server does not say where its attachments are") from exc
    if not (isinstance(base, str) and re.fullmatch(r"https://[^/\s]+(/\S*)?/", base)):
        raise IntermediatesError("the attachments' base URL is not an https directory: %r" % (base,))
    return base


def _open_bundle(base: str, attempts: int) -> zipfile.ZipFile:
    url = base + INTERMEDIATES_BUNDLE_PATH
    raw = _with_retries(lambda: _get(url), "the intermediates bundle", attempts)
    try:
        return zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise IntermediatesError("the intermediates bundle is not a zip: %s" % exc) from exc


def _attachment_bytes(bundle: zipfile.ZipFile, base: str, record: dict, attempts: int) -> bytes:
    """The bytes of a record's attachment: the bundle's entry named by the record's id and, when the bundle lacks it, the attachment itself."""
    rid = record.get("id")
    try:
        info = bundle.getinfo(rid) if isinstance(rid, str) else None
    except KeyError:
        info = None
    if info is not None:
        if info.file_size > _MAX_ATTACHMENT:
            raise IntermediatesError("record %s: its bundle entry is %d bytes" % (rid, info.file_size))
        return bundle.read(info)
    location = (record.get("attachment") or {}).get("location")
    if not isinstance(location, str) or not location:
        raise IntermediatesError("record %s: neither in the bundle nor with a location" % rid)
    url = base + location
    return _with_retries(lambda: _get(url), "the attachment of record %s" % rid, attempts)


def build_list(changeset: dict, base: str, bundle: zipfile.ZipFile, attempts: int) -> dict:
    """The file's content, from the collection's changeset and its attachments, or `IntermediatesError`."""
    timestamp = changeset.get("timestamp")
    records = changeset.get("changes")
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp <= 0 or not isinstance(records, list):
        raise IntermediatesError("the changeset has no timestamp or no records")
    records = [r for r in records if isinstance(r, dict) and not r.get("deleted")]
    if not records:
        raise IntermediatesError("the collection has no records")
    ids = [r.get("id") for r in records]
    if len(set(ids)) != len(ids):
        raise IntermediatesError("two records have the same id")
    certs = [_verified_cert(r, _attachment_bytes(bundle, base, r, attempts)) for r in records]
    hashes = sorted(c["derHash"] for c in certs)
    if len(set(hashes)) != len(hashes):
        raise IntermediatesError("two records are the same certificate")
    if len(certs) != len(records):
        raise IntermediatesError("%d certificates for %d records" % (len(certs), len(records)))
    certs.sort(key=lambda c: c["derHash"])
    return {
        "format": 1,
        "collection": _COLLECTION,
        "collection_timestamp": timestamp,
        "fetched_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(certs),
        "set_sha256": hashlib.sha256("\n".join(hashes).encode("ascii")).hexdigest(),
        "certs": certs,
    }


def _compact(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def fetch_intermediates(directory: Path, expected: int, attempts: int) -> dict:
    """Download the intermediates, verify them and write `directory/intermediates.json` (compact); returns the listing.

    `expected` is the collection's timestamp from the changes feed (or 0): it only busts the cache in front of the server. Three requests at most besides the
    certificates the bundle lacks: the changeset, the server's info (where the attachments are) and the bundle. Anything that does not add up is
    `IntermediatesError`; the caller works in a staging directory, so nothing is cleaned up here."""
    url = SECURITY_STATE_CHANGESET_URL_TEMPLATE.format(collection=INTERMEDIATES_COLLECTION_ID, expected=expected)
    changeset = _get_json(url, attempts)
    base = _attachments_base(attempts)
    bundle = _open_bundle(base, attempts)
    listing = build_list(changeset, base, bundle, attempts)
    (Path(directory) / INTERMEDIATES_FILE_NAME).write_bytes(_compact(listing))
    return listing
