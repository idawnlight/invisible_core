"""The list of preloaded intermediate certificates, declared by the core.

A retail Firefox has the intermediates of the public web in `cert_storage` from the first second: it takes them from Mozilla's Remote Settings collection
`security-state/intermediates`. The engine does not sync that collection any more (a sync reaches Mozilla's servers from the engine's own process, on a clock
nobody declared), so the core DECLARES the list: this module downloads it from the same service Firefox uses, from the USER's Python, verifies it and keeps
it in the cache as `intermediates.json`; the launch hands the engine its path (the pref `INTERMEDIATES_PREF`, written once, by `launch.write_user_js`, the one writer of `user.js`).

THE FILE (read by the engine; its format is the engine's contract and is changed with it):

    {"format":1,"collection":"security-state/intermediates","collection_timestamp":<int>,"fetched_utc":"...Z","count":N,
     "set_sha256":"<hex sha256 of the derHashes, sorted, joined by \\n>",
     "certs":[{"derHash":"<b64>","cert":"<b64 DER>","subject":"<b64 DER of the subject>"}]}

compact, UTF-8, LF, the certs sorted by derHash; `SOURCES.json` beside it says where it came from. The version of a copy is the collection's own timestamp: one
directory per version in the cache, the highest wins (`_cached_asset`).

TWO ROADS, and only the second ever touches the network on a warm cache:
  * `ensure_intermediates()` is what a launch calls BEFORE the browser starts. A copy in the cache is returned at once, with NO request, whatever its age:
    a launch never waits for Mozilla and starts no thread for it. Only a cold cache downloads, in line (there is nothing else to declare).
  * `update_intermediates()` is what `invisible-playwright fetch` calls, because the user asked for it: it asks the changes feed (a few hundred bytes)
    for the collection's timestamp EVERY time and, when it is newer than the cache's, downloads, verifies and puts the new version in place. There is no
    schedule and no state file: the user's command is the clock, and the answer of the feed is the only thing that decides.

NOTHING THAT DOES NOT ADD UP IS KEPT. Every record is checked against what the server itself says about it (the sha256 of the attachment, the hash of the
DER, the subject) and the number of certificates against the number of records; one piece that fails refuses the whole download and the copy in the cache stays
as it was. The checks use only the standard library (a minimal DER reader for the subject, below): a certificate library would be a dependency for one field.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

import requests

from . import _cached_asset as _asset
from . import environment
from .constants import (
    INTERMEDIATES_BUNDLE_PATH,
    INTERMEDIATES_CHANGESET_URL_TEMPLATE,
    INTERMEDIATES_FILE_NAME,
    INTERMEDIATES_LATEST_URL,
    INTERMEDIATES_SERVER_INFO_URL,
    INTERMEDIATES_SOURCES_NAME,
    REMOTE_SETTINGS_SERVER,
)
from .download import DOWNLOAD_ATTEMPTS, _with_retries, state_dir

__all__ = ["ensure_intermediates", "update_intermediates", "intermediates_path"]

#: The collection's name as the file says it.
_COLLECTION = "security-state/intermediates"

#: The one cold download in flight in this process: the callers of a cold cache share it.
_SLOT = _asset.FlightSlot()

#: The warning about a cold cache with no network is printed once per process.
_WARNED = False

#: Bounds on what a server may hand back: the whole bundle, one attachment, one JSON answer. A certificate is about 2 KB and the bundle about 4 MB; the
#: bounds only stop a wrong answer from filling memory.
_MAX_BODY = 64 << 20
_MAX_ATTACHMENT = 1 << 20


class IntermediatesError(RuntimeError):
    """What was downloaded does not add up, or cannot be used. Never retried: asking again returns the same bytes."""


# --- the cache -------------------------------------------------------------------------------------------------------------------------------------

def _root() -> Path:
    return state_dir("intermediates")


def _version_of(path: Path) -> int:
    name = path.parent.name
    return int(name) if name.isdigit() else -1


def _cached_file() -> Optional[Path]:
    """The newest cached `intermediates.json` (the directory names are the collection's timestamps: numbers, so they are ordered as numbers), or None."""
    return _asset.newest_file(_root(), "*/" + INTERMEDIATES_FILE_NAME, key=_version_of)


def intermediates_path() -> Optional[Path]:
    """The cached list, or None. Nothing is asked of the network."""
    return _cached_file()


def _warn_once(message: str) -> None:
    global _WARNED
    if _WARNED:
        return
    _WARNED = True
    print("invisible_core: " + message, file=sys.stderr, flush=True)


# --- the network (ONE seam) --------------------------------------------------------------------------------------------------------------------------

def _get(url: str) -> bytes:
    """The bytes of `url`. The only function of this module that reaches the network: a failure is a `requests` exception, so `_with_retries` reads its
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


def _sources_of(listing: dict, expected: int, base: str) -> dict:
    return {
        "server": REMOTE_SETTINGS_SERVER,
        "urls": [
            INTERMEDIATES_CHANGESET_URL_TEMPLATE.format(expected=expected),
            INTERMEDIATES_SERVER_INFO_URL,
            base + INTERMEDIATES_BUNDLE_PATH,
        ],
        "collection_timestamp": listing["collection_timestamp"],
        "count": listing["count"],
        "set_sha256": listing["set_sha256"],
        "date": listing["fetched_utc"],
    }


def _write_files(directory: Path, listing_bytes: bytes, sources_bytes: bytes) -> None:
    """The two files of a version, in a directory nobody else can see yet."""
    (directory / INTERMEDIATES_FILE_NAME).write_bytes(listing_bytes)
    (directory / INTERMEDIATES_SOURCES_NAME).write_bytes(sources_bytes)


def _download_and_publish(attempts: int, expected: int) -> Path:
    """Download, verify and put a new version in the cache; its path. Raises on anything that does not add up, with the cache as it was.

    The version is built in a directory BESIDE the root and renamed into it in one step, so it is seen complete or not at all and a process that dies in the
    middle leaves nothing in the root."""
    changeset = _get_json(INTERMEDIATES_CHANGESET_URL_TEMPLATE.format(expected=expected), attempts)
    base = _attachments_base(attempts)
    bundle = _open_bundle(base, attempts)
    listing = build_list(changeset, base, bundle, attempts)
    version = str(listing["collection_timestamp"])
    root = _root()
    staging = _asset.new_staging(root, ".tmp-intermediates-%s-" % version)
    try:
        _write_files(staging, _compact(listing),
                     json.dumps(_sources_of(listing, expected, base), indent=2).encode("utf-8") + b"\n")
        dst = root / version
        _asset.put_in_place(staging, dst, lambda d: (d / INTERMEDIATES_FILE_NAME).is_file())
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    found = dst / INTERMEDIATES_FILE_NAME
    if not found.is_file():
        raise IntermediatesError("the intermediates list is not in %s after it was put in place" % dst)
    newest = _cached_file()
    _asset.prune_dirs(root, (newest or found).parent.name)
    return found


# --- the launch: the cold road, in line ----------------------------------------------------------------------------------------------------------------

def _fetch_cold() -> Path:
    """Nothing is cached: download in line, one process of the machine at a time, with the attempts a download has. Whoever gets the lock after another
    process finished uses what that one left."""
    def fetch_locked(_have):
        return _download_and_publish(DOWNLOAD_ATTEMPTS, 0)

    return _asset.check_and_fetch(
        _asset.machine_lock(_root(), _asset.LOCK_WAIT_S),
        cached=lambda: _cached_file(),
        state_due=lambda: False,  # a copy is a copy: with one there is nothing to fetch
        fetch_locked=fetch_locked,
    )


def ensure_intermediates(*, inline: bool = True) -> Optional[Path]:
    """The intermediates file to declare, or None.

    Resolution order:
      1. ``STEALTHFOX_INTERMEDIATES`` -> that file (user-supplied / test); a missing one is an error.
      2. A copy is cached -> it, with NO request, however old it is: a newer list is looked for only by `update_intermediates` (the `fetch` command).
      3. Cold cache and `inline` -> download in line (the callers of one process share it), with the attempts of a download.
      4. Cold cache and no network (or `inline=False`) -> None, with a warning on stderr once per process: the browser starts without the list, which is the
         state it was in before the core declared one.
    """
    override = os.environ.get(environment.INTERMEDIATES)
    if override:
        p = Path(override)
        if not p.is_file():
            raise RuntimeError(f"{environment.INTERMEDIATES} points to a missing file: {p}")
        return p
    cached = _cached_file()
    if cached is not None:
        return cached
    if not inline:
        return None
    try:
        return _asset.ensure_once(
            _SLOT,
            cached=lambda: _cached_file(),
            check_due=lambda: True,
            mark_checked=lambda: None,
            fetch=lambda: _fetch_cold(),
        )
    except Exception as exc:
        _warn_once("the list of preloaded intermediate certificates could not be downloaded (%s); the browser starts without it. "
                   "Connect once to download it, or set %s to a local intermediates.json." % (exc, environment.INTERMEDIATES))
        return None


# --- the user's `fetch`: is there a newer list? ------------------------------------------------------------------------------------------------------------

def _latest_timestamp(attempts: int) -> int:
    """The collection's timestamp, from the changes feed (a few hundred bytes), not from the collection."""
    feed = _get_json(INTERMEDIATES_LATEST_URL, attempts)
    for entry in feed.get("changes", []) if isinstance(feed, dict) else []:
        if entry.get("bucket") == "security-state" and entry.get("collection") == "intermediates":
            stamp = entry.get("last_modified")
            if isinstance(stamp, int) and not isinstance(stamp, bool) and stamp > 0:
                return stamp
    raise IntermediatesError("the changes feed does not list the collection")


def update_intermediates() -> Tuple[Optional[Path], bool]:
    """Ask whether the collection has a newer list than the cache's and, if so, download, verify and put it in place. `(path, changed)`: the list to declare
    (None when there is none) and whether this call put a new version in the cache.

    Called by `invisible-playwright fetch`, so it asks EVERY time (a few hundred bytes from the changes feed) and downloads only when the feed's timestamp is
    greater than the cached version (or the cache is empty). One process of the machine at a time; whoever gets the lock after another finished re-reads what
    that one left. ``STEALTHFOX_INTERMEDIATES`` set -> nothing is asked or downloaded: `(that path, False)`. No network, or anything that does not add up ->
    the cache is as it was, one warning on stderr, and no exception."""
    override = os.environ.get(environment.INTERMEDIATES)
    if override:
        return Path(override), False
    try:
        with _asset.machine_lock(_root(), _asset.LOCK_WAIT_S):
            have = _cached_file()
            latest = _latest_timestamp(DOWNLOAD_ATTEMPTS)
            if have is not None and latest <= _version_of(have):
                return have, False
            return _download_and_publish(DOWNLOAD_ATTEMPTS, latest), True
    except Exception as exc:
        kept = _cached_file()
        print("invisible_core: could not look for a newer list of preloaded intermediate certificates (%s); %s" % (
            exc, "the one in the cache stays" if kept is not None else "there is none in the cache, and the browser starts without it"),
            file=sys.stderr, flush=True)
        return kept, False
