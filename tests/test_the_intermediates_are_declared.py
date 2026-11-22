"""The preloaded intermediate certificates are downloaded and verified by the core: one of the three inputs of the engine's generate mode.

A retail Firefox has the intermediates of the public web in cert_storage from its first second (Mozilla's Remote Settings collection `security-state/intermediates`). The core
downloads the collection (from the user's Python), verifies every record against what the server itself says about it, and writes `intermediates.json`; where it is kept, when it
is renewed and how it reaches a profile is `_security_state.py`'s (tests/test_the_security_state_is_ready_in_every_profile.py). Nothing here reaches Mozilla: the transport
(`_intermediates._get`, the module's one network seam) is a fake that serves a synthetic collection built from certificates made in this file. No test measures a time.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
import requests

from invisible_core import _intermediates as im
from invisible_core import download
from invisible_core.constants import (
    INTERMEDIATES_BUNDLE_PATH,
    INTERMEDIATES_FILE_NAME,
    INTERMEDIATES_SERVER_INFO_URL,
    SECURITY_STATE_CHANGESET_URL_TEMPLATE,
)

pytestmark = pytest.mark.unit

BASE = "https://attachments.invalid/"


# --- certificates made here (DER by hand: the core reads only the subject, and the test must not need a library either) ------------------------------------

def _tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + body


def _name(cn: str) -> bytes:
    atv = _tlv(0x30, _tlv(0x06, b"\x55\x04\x03") + _tlv(0x0C, cn.encode()))
    return _tlv(0x30, _tlv(0x31, atv))


def make_cert(cn: str) -> bytes:
    algorithm = _tlv(0x30, _tlv(0x06, b"\x2a\x03\x04"))
    validity = _tlv(0x30, _tlv(0x17, b"260101000000Z") + _tlv(0x17, b"360101000000Z"))
    tbs = _tlv(0x30, _tlv(0xA0, _tlv(0x02, b"\x02")) + _tlv(0x02, b"\x01") + algorithm + _name("an issuer") + validity
               + _name(cn) + _tlv(0x30, b""))
    return _tlv(0x30, tbs + algorithm + _tlv(0x03, b"\x00\x01"))


def to_pem(der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()



class Mozilla:
    """The collection and its server, as the transport answers them. `calls` is every URL asked, in order."""

    def __init__(self, timestamp: int, names=("Alpha CA", "Bravo CA", "Charlie CA")):
        self.timestamp = timestamp
        self.calls: list = []
        self.records: list = []
        self.attachments: dict = {}
        self.missing_from_bundle: set = set()
        self.offline = False
        for i, name in enumerate(names):
            self.add(name, "rec-%d" % i)

    def add(self, name: str, rid: str) -> dict:
        der = make_cert(name)
        pem = to_pem(der)
        record = {
            "id": rid,
            "derHash": base64.b64encode(hashlib.sha256(der).digest()).decode(),
            "subjectDN": base64.b64encode(_name(name)).decode(),
            "attachment": {"hash": hashlib.sha256(pem).hexdigest(), "size": len(pem), "location": "sec/%s.pem" % rid},
        }
        self.records.append(record)
        self.attachments[rid] = pem
        return record

    def bundle(self) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            for r in self.records:
                if r["id"] in self.missing_from_bundle:
                    continue
                z.writestr(r["id"] + ".meta.json", json.dumps(r))
                z.writestr(r["id"], self.attachments[r["id"]])
        return out.getvalue()

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        if self.offline:
            raise requests.ConnectionError("no route to host")
        if url == SECURITY_STATE_CHANGESET_URL_TEMPLATE.format(collection="intermediates", expected=self.timestamp):
            return json.dumps({"timestamp": self.timestamp, "metadata": {}, "changes": self.records}).encode()
        if url == INTERMEDIATES_SERVER_INFO_URL:
            return json.dumps({"capabilities": {"attachments": {"base_url": BASE}}}).encode()
        if url == BASE + INTERMEDIATES_BUNDLE_PATH:
            return self.bundle()
        if url.startswith(BASE + "sec/"):
            return self.attachments[url[len(BASE + "sec/"):-len(".pem")]]
        raise AssertionError("an address nobody serves: %s" % url)


@pytest.fixture
def mozilla(monkeypatch):
    m = Mozilla(timestamp=2000)
    monkeypatch.setattr(im, "_get", m)
    monkeypatch.setattr(download, "_SLEEP", lambda seconds: None)   # the retries ask again at once
    monkeypatch.setattr(download, "_note", lambda message: None)
    return m


@pytest.fixture
def out(tmp_path) -> Path:
    d = tmp_path / "staging"
    d.mkdir()
    return d


# --- c. a record that does not add up refuses the whole download ------------------------------------------------------------------------------------

def _corrupt_hash(m):
    m.records[1]["attachment"]["hash"] = "0" * 64


def _corrupt_der_hash(m):
    m.records[1]["derHash"] = base64.b64encode(b"x" * 32).decode()


def _corrupt_subject(m):
    m.records[1]["subjectDN"] = base64.b64encode(_name("Somebody Else")).decode()


def _corrupt_size(m):
    m.records[1]["attachment"]["size"] += 1


def _swapped_bytes(m):
    """The bytes of one attachment are another certificate's, and the record was left as it was."""
    m.attachments["rec-1"] = m.attachments["rec-0"]



@pytest.mark.parametrize("corrupt", [_corrupt_hash, _corrupt_der_hash, _corrupt_subject, _corrupt_size, _swapped_bytes])
def test_a_certificate_that_does_not_add_up_refuses_the_whole_download_and_writes_nothing(mozilla, out, corrupt):
    """The known-bad: a list kept although one record's sha256, derHash or subject disagrees with its certificate. A refusal is total: `IntermediatesError`, and not a file
    is written in the directory the caller gave."""
    corrupt(mozilla)
    with pytest.raises(im.IntermediatesError):
        im.fetch_intermediates(out, 2000, 1)
    assert list(out.iterdir()) == []


def test_a_collection_with_no_records_is_refused(mozilla, out):
    mozilla.records.clear()
    with pytest.raises(im.IntermediatesError, match="no records"):
        im.fetch_intermediates(out, 2000, 1)
    assert list(out.iterdir()) == []


def test_two_records_of_one_certificate_are_refused(mozilla, out):
    mozilla.add("Alpha CA", "rec-again")
    with pytest.raises(im.IntermediatesError, match="same certificate"):
        im.fetch_intermediates(out, 2000, 1)
    assert list(out.iterdir()) == []


def test_a_server_that_does_not_say_where_its_attachments_are_is_refused(mozilla, out, monkeypatch):
    real = mozilla.__call__
    monkeypatch.setattr(im, "_get", lambda url: b"{}" if url == INTERMEDIATES_SERVER_INFO_URL else real(url))
    with pytest.raises(im.IntermediatesError, match="attachments"):
        im.fetch_intermediates(out, 2000, 1)


def test_an_unreachable_server_is_the_transport_s_error_and_writes_nothing(mozilla, out):
    mozilla.offline = True
    with pytest.raises(requests.ConnectionError):
        im.fetch_intermediates(out, 2000, 1)
    assert list(out.iterdir()) == []


# --- the rest of the contract: what the file is, and the road for what the bundle lacks ---------------------------------------------------------------

def test_the_download_asks_the_changeset_the_server_and_the_bundle_and_the_file_has_the_declared_format(mozilla, out):
    listing = im.fetch_intermediates(out, 2000, 1)
    assert mozilla.calls == [
        SECURITY_STATE_CHANGESET_URL_TEMPLATE.format(collection="intermediates", expected=2000),
        INTERMEDIATES_SERVER_INFO_URL,
        BASE + INTERMEDIATES_BUNDLE_PATH,
    ]
    assert [p.name for p in out.iterdir()] == [INTERMEDIATES_FILE_NAME]
    raw = (out / INTERMEDIATES_FILE_NAME).read_bytes()
    assert b"\r" not in raw and b"\n" not in raw, "compact, LF"
    assert json.loads(raw) == listing
    assert list(listing) == ["format", "collection", "collection_timestamp", "fetched_utc", "count", "set_sha256", "certs"]
    assert listing["format"] == 1 and listing["collection"] == "security-state/intermediates" and listing["collection_timestamp"] == 2000
    hashes = [c["derHash"] for c in listing["certs"]]
    assert hashes == sorted(hashes) and listing["count"] == len(hashes) == 3
    assert listing["set_sha256"] == hashlib.sha256("\n".join(hashes).encode()).hexdigest()
    cert = listing["certs"][0]
    assert list(cert) == ["derHash", "cert", "subject"]
    der = base64.b64decode(cert["cert"])
    assert base64.b64encode(hashlib.sha256(der).digest()).decode() == cert["derHash"]
    assert base64.b64decode(cert["subject"]) == im.subject_der(der)


def test_a_record_the_bundle_lacks_is_fetched_by_its_own_location(mozilla, out):
    mozilla.missing_from_bundle = {"rec-2"}
    listing = im.fetch_intermediates(out, 2000, 1)
    assert listing["count"] == 3
    assert BASE + "sec/rec-2.pem" in mozilla.calls
    assert BASE + "sec/rec-0.pem" not in mozilla.calls


def test_the_module_keeps_no_cache_and_no_road_of_its_own():
    """The cache, the launch and `fetch` are `_security_state`'s: what this module no longer has must not come back as a second road."""
    for name in ("ensure_intermediates", "update_intermediates", "intermediates_path", "_root", "_cached_file", "_SLOT", "_WARNED"):
        assert not hasattr(im, name), name


#: A real intermediate of Mozilla's collection (record 515b5465-..., SZAFIR Trusted CA6): the DER reader meets a certificate it did not make.
REAL_CERT_B64 = (
    "MIIFmTCCBIGgAwIBAgIUFobWbkmXQcNY82H+JTMWCRDxtXQwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCUEwxKDAmBgNVBAoM"
    "H0tyYWpvd2EgSXpiYSBSb3psaWN6ZW5pb3dhIFMuQS4xGDAWBgNVBAMMD1NaQUZJUiBST09UIENBMjAeFw0yNDEwMjEwODAwNTZa"
    "Fw0zNDEwMjEwODAwNTZaMFQxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMRsw"
    "GQYDVQQDDBJTWkFGSVIgVHJ1c3RlZCBDQTYwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4J0tw3SWSeKcGCcXOVZ2V"
    "c3rcFo77SF7APLLWXtjcRkL8jq9SmZSYVoo9NdiytmHaQfOVI5jZBKt4ER5OS8+e+/BUZPz1TeGc7p5fhSAuXC3CizHQD93txK2r"
    "aiuIwqZqLpAb22Je1MdFyQh1ICRgombZ7LRyVx/j6RfJkvQe3sJzMzBHRRyucD66MCi8oUH6w5j2k2y1X14ONpHtTFs9nCGiEY3U"
    "XjvlPfSt1b4PljfwZj5l7rDRl4SyMhsQhef+rxgtkqp3nyT4OLIfi+ynEiiMmFoZWveudEZQHZ+IK6UDASSCwq1zn4ISC2VT62yD"
    "GqMPBbCyJTfFs6VuJeUn28ydp80ZOlfSUp5/+pxKbrboDDJxQi3LuI0x/ocysSMucPwpp7HSesYYmFnI0Jp9YBGM19keFCHYjjCi"
    "c3J4grKX04Al/UDNit7IA41gDxmAjRiQahSx3o6yItW241PyTGpeVHbJ0171BRcJqjnaUiAl6QgkQ8nnY8G8Q2aW4wwRahEPTIql"
    "BOFMD+j2d5xIdWh2vpfX0+/4hivtJgHwUh2x4koCwcMZb3BIAT7aSem23d1nLwYNyu0Om6KD0ye0KX/YM9kidd+HRkU3rkrqrCgN"
    "0lMfiuD6FCpViq9ctVIrE2KjAxvtLHhhuTRZP8VYGdNx88zahRtp73nFjca27QIDAQABo4IBZDCCAWAwDwYDVR0TAQH/BAUwAwEB"
    "/zB6BggrBgEFBQcBAQRuMGwwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmVsZWt0cm9uaWN6bnlwb2RwaXMucGwwOgYIKwYBBQUH"
    "MAKGLmh0dHA6Ly9jZHAuZWxla3Ryb25pY3pueXBvZHBpcy5wbC9yb290X2NhMi5jcnQwIQYDVR0gBBowGDAIBgZngQwBAgIwDAYK"
    "KoRoAYb3IwECBjAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFC4WqUoY"
    "tcvM9W9Q8yNf+F3nrPDIMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jZHAuZWxla3Ryb25pY3pueXBvZHBpcy5wbC9yb290X2Nh"
    "Mi5jcmwwHQYDVR0OBBYEFAQC5AVJAffed7/r+4W/H0TMPvG0MA0GCSqGSIb3DQEBCwUAA4IBAQBPl2jU755j+FBvSsgTR5GyREO7"
    "WuRBflAqk7TURuGbjBkL6pB93QWVFTpW36+yu6C3J1ippS+fuDR7psHc618/W2mznczu6TJkqgINI+6VYftJZU33Dm5SLFeFkPHp"
    "+V1hXAlntZPPT++h4IOexpCLfXmW3hRbZoVdXHIFHLB35liPW2942BHy94DpvMHaS3e8UneNpKsoCgMUsyMVoxG7O8TUPtoD3te1"
    "RS3CdTspIJGKQ2zNTcAcIJxKWQotT8DgQLIfIlRoguVQH2c9UhYrwKbPM2KV60wQvea2pxPT5vGMH3aBePk4W6gJOWigSPXsL0PO"
    "AtsJlF4by9GjJQpQ"
)
REAL_SUBJECT_B64 = (
    "MFQxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMRswGQYDVQQDDBJTWkFGSVIg"
    "VHJ1c3RlZCBDQTY="
)


def test_the_subject_of_a_real_certificate_is_read_as_mozilla_declares_it():
    assert im.subject_der(base64.b64decode(REAL_CERT_B64)) == base64.b64decode(REAL_SUBJECT_B64)


@pytest.mark.parametrize("cut", [0, 1, 2, 10, 40])
def test_a_truncated_certificate_is_refused_by_the_reader(cut):
    der = make_cert("Alpha CA")
    with pytest.raises(im.IntermediatesError):
        im.subject_der(der[:cut] if cut < 5 else der[:len(der) - cut])

