"""OneCRL and the CRLite filters are built from Remote Settings the way a retail Firefox 159 reads them (`security/manager/ssl/RemoteSecuritySettings.sys.mjs`).

Nothing here reaches Mozilla: the transport (`_intermediates._get`, the one network seam of the core) is a fake that serves a synthetic changeset and synthetic
attachments, and records every URL it was asked. No test measures a time or reads a clock: the asserts are on what was built, what was asked and what was refused.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
import requests

from invisible_core import _intermediates as im
from invisible_core import _revocations as rv
from invisible_core import download
from invisible_core.constants import CRLITE_FILE_NAME, ONECRL_FILE_NAME

pytestmark = pytest.mark.unit

BASE = "https://attachments.invalid/"
UTC = "2026-11-20T10:00:00Z"
EXPR = "env.version|versionCompare('133.!') >= 0 && '%s' == 'security.pki.crlite_channel'|preferenceValue('none')"
DEFAULT = EXPR % "default"
COMPAT = EXPR % "compat"


class Mozilla:
    """The service, as the transport answers it. `calls` is every URL asked, in order."""

    def __init__(self):
        self.calls: list = []
        self.answers: dict = {}
        self.failures: list = []   # exceptions raised by the next calls, one per call

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        if self.failures:
            raise self.failures.pop(0)
        if url not in self.answers:
            raise AssertionError("an address nobody serves: %s" % url)
        return self.answers[url]


@pytest.fixture
def mozilla(monkeypatch):
    server = Mozilla()
    monkeypatch.setattr(im, "_get", server)
    monkeypatch.setattr(download, "_SLEEP", lambda seconds: None)   # the retries ask again at once
    monkeypatch.setattr(download, "_note", lambda message: None)
    return server


def payload(n: int) -> bytes:
    return (b"filter-%d-" % n) * (n + 3)


def crlite(rid: str, n: int, *, incremental: bool, expr=DEFAULT, data=None, filename=None) -> dict:
    data = payload(n) if data is None else data
    record = {
        "id": rid,
        "incremental": incremental,
        "channel": "default",
        "attachment": {
            "filename": filename or ("2026111%d-0-default.filter%s" % (n, ".delta" if incremental else "")),
            "hash": hashlib.sha256(data).hexdigest(),
            "location": "security-state-staging/cert-revocations/%d.bin" % n,
            "mimetype": "application/x-protobuf",
            "size": len(data),
        },
        "last_modified": 1000 + n,
    }
    if expr is not None:
        record["filter_expression"] = expr
    return record


def changeset(records, timestamp=1794348206673) -> dict:
    return {"timestamp": timestamp, "metadata": {}, "changes": records}


def serve(server: Mozilla, records) -> None:
    for r in records:
        n = int(r["attachment"]["location"].split("/")[-1].split(".")[0])
        server.answers[BASE + r["attachment"]["location"]] = payload(n)


def urls_of_attachments(server: Mozilla) -> list:
    return [u for u in server.calls if u.startswith(BASE)]


def no_reuse(_sha: str):
    return None


# --- the filter expressions ------------------------------------------------------------------------------------------------------------------------------

def test_the_expressions_mozilla_publishes_are_read_as_firefox_reads_them():
    held = lambda e, **kw: rv.filter_expression_holds(e, version="159.0", channel=kw.get("channel", "default"))
    assert held(DEFAULT) is True
    assert held(COMPAT) is False
    assert held(COMPAT, channel="compat") is True
    # a version below the threshold is dropped: 132.0 < 133.!
    assert rv.filter_expression_holds(DEFAULT, version="132.0", channel="default") is False
    assert rv.filter_expression_holds(DEFAULT, version="133.0", channel="default") is True
    # any version literal is understood
    assert rv.filter_expression_holds(DEFAULT.replace("133.!", "200.!"), version="159.0", channel="default") is False


def test_a_record_without_an_expression_is_kept():
    assert rv.filter_expression_holds(None, version="159.0", channel="default") is True
    assert rv.filter_expression_holds("", version="159.0", channel="default") is True


@pytest.mark.parametrize("expr", [
    "true",
    DEFAULT.replace(">= 0", "> 0"),
    DEFAULT.replace(" && ", " || "),
    DEFAULT + " ",
    DEFAULT.replace("preferenceValue('none')", "preferenceValue('x')"),
    "env.version|versionCompare('133.!') >= 0",
    DEFAULT.replace("security.pki.crlite_channel", "security.other"),
    7,
])
def test_an_expression_nobody_taught_the_parser_is_refused(expr):
    with pytest.raises(rv.RevocationsError):
        rv.filter_expression_holds(expr, version="159.0", channel="default")


def test_the_error_is_the_one_callers_already_catch():
    assert issubclass(rv.RevocationsError, im.IntermediatesError)


# --- nsVersionComparator.cpp -----------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("159.0", "133.!", 1),               # the threshold of the CRLite records
    ("132.0", "133.!", -1),
    ("133.0", "133.!", 1),               # "0" has no string, "!" has one, and no string is AFTER a string
    ("133.!", "133.!", 0),
    ("1.0", "1.0", 0),
    ("1.0", "1.0.0", 0),                 # a missing part is 0
    ("1.0.0", "1", 0),
    ("0010", "10", 0),
    ("1.0.1", "1.0", 1),
    ("1.9", "1.10", -1),                 # numbers, not strings
    ("1.0a", "1.0", -1),                 # a pre-release is before the release
    ("1.0", "1.0a", 1),
    ("1.0pre1", "1.0pre2", -1),
    ("1.0pre10", "1.0pre9", 1),
    ("1.0pre1", "1.0", -1),
    ("1.0a1", "1.0b1", -1),              # the strings are compared as strings
    ("1.0b1", "1.0b2", -1),
    ("1.0a1b", "1.0a1c", -1),            # extraD
    ("1.0a1", "1.0a1b", 1),              # no extraD is after an extraD
    ("1.0+", "1.1pre", 0),               # '+' is one more and the string "pre"
    ("1.0+", "1.0", 1),
    ("1.*", "1.99999", 1),               # '*' is INT32_MAX
    ("*", "5", 1),
    ("*", "*", 0),
    ("1.", "1", 0),                      # a trailing dot adds no part
    ("2147483648", "1", -1),             # out of int32: ns_strtol answers 0
    ("1.0", "1.0.1", -1),
    ("abc", "abd", -1),                  # no number at all: numA 0 and the string
    ("a\u00ff", "a\u007f", -1),          # the char is signed: bytes above 0x7f sort BEFORE ASCII
])
def test_version_compare_is_nsVersionComparator(a, b, expected):
    assert rv.version_compare(a, b) == expected
    assert rv.version_compare(b, a) == -expected


# --- the CRLite records ----------------------------------------------------------------------------------------------------------------------------------

def test_the_full_filter_is_chosen_and_the_deltas_come_in_id_order_whatever_the_changeset_order():
    records = [
        crlite("c-delta", 3, incremental=True),
        crlite("a-full", 1, incremental=False),
        crlite("d-delta", 4, incremental=True),
        crlite("b-delta", 2, incremental=True),
    ]
    full, deltas = rv.crlite_records(changeset(records))
    assert full["id"] == "a-full"
    assert [r["id"] for r in deltas] == ["b-delta", "c-delta", "d-delta"]


def test_the_records_of_another_channel_or_of_an_older_firefox_are_not_kept():
    records = [
        crlite("a", 1, incremental=False),
        crlite("b", 2, incremental=True),
        crlite("c-compat-full", 5, incremental=False, expr=COMPAT),
        crlite("d-compat", 6, incremental=True, expr=COMPAT),
        crlite("e-future", 7, incremental=True, expr=DEFAULT.replace("133.!", "999.!")),
        crlite("f-free", 8, incremental=True, expr=None),
    ]
    full, deltas = rv.crlite_records(changeset(records))
    assert full["id"] == "a"
    assert [r["id"] for r in deltas] == ["b", "f-free"]
    full, deltas = rv.crlite_records(changeset(records), channel="compat")
    assert full["id"] == "c-compat-full"
    assert [r["id"] for r in deltas] == ["d-compat", "f-free"]


def test_deleted_records_are_dropped():
    gone = dict(crlite("a-gone", 9, incremental=False), deleted=True)
    full, deltas = rv.crlite_records(changeset([gone, crlite("b", 1, incremental=False), crlite("c", 2, incremental=True)]))
    assert full["id"] == "b" and [r["id"] for r in deltas] == ["c"]


@pytest.mark.parametrize("records", [
    [crlite("a", 1, incremental=True)],                                              # no full filter
    [crlite("a", 1, incremental=False), crlite("b", 2, incremental=False)],           # two
    [],                                                                               # nothing
])
def test_a_collection_without_exactly_one_full_filter_is_refused(records):
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset(records))


def test_a_second_full_filter_of_another_channel_does_not_count():
    records = [crlite("a", 1, incremental=False), crlite("b", 2, incremental=False, expr=COMPAT)]
    full, deltas = rv.crlite_records(changeset(records))
    assert full["id"] == "a" and deltas == []


def test_two_records_with_the_same_id_are_refused():
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset([crlite("a", 1, incremental=False), crlite("a", 2, incremental=True)]))


def test_two_records_with_the_same_attachment_are_refused():
    one = crlite("a", 1, incremental=False)
    two = crlite("b", 2, incremental=True)
    two["attachment"]["hash"] = one["attachment"]["hash"]
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset([one, two]))


@pytest.mark.parametrize("name", [
    "../x.filter", "a/b.filter", "a\\b.filter", "..", "", "C:evil.filter", "C:\\evil.filter", "/abs.filter", "x..y.filter", "con.filter",
    "trailing.", ".hidden", "with space.filter", "x" * 300, "crlite.json", None, 7,
])
def test_a_filename_that_is_not_a_plain_basename_is_refused(name):
    full = crlite("a", 1, incremental=False)
    full["attachment"]["filename"] = name
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset([full]))


@pytest.mark.parametrize("name", ["crlite.filter", "CRLITE.FILTER", "Crlite.Filter"])
@pytest.mark.parametrize("incremental", [False, True], ids=["full", "delta"])
def test_an_attachment_named_as_the_engine_names_the_full_filter_is_refused(name, incremental):
    """The engine writes the full filter as `security_state/crlite.filter`: an attachment of that name, full or delta, in any case, is refused."""
    full = crlite("a", 1, incremental=False)
    records = [full]
    if incremental:
        delta = crlite("b", 2, incremental=True, filename=name)
        records.append(delta)
    else:
        full["attachment"]["filename"] = name
    with pytest.raises(rv.RevocationsError, match="security_state"):
        rv.crlite_records(changeset(records))


@pytest.mark.parametrize("name", ["a/b.delta", "a\\b.delta", "..\\crlite.filter", "../crlite.filter", "sub/crlite.filter"])
@pytest.mark.parametrize("incremental", [False, True], ids=["full", "delta"])
def test_a_filename_with_a_path_separator_is_refused_for_a_full_filter_and_for_a_delta(name, incremental):
    full = crlite("a", 1, incremental=False)
    records = [full]
    if incremental:
        records.append(crlite("b", 2, incremental=True, filename=name))
    else:
        full["attachment"]["filename"] = name
    with pytest.raises(rv.RevocationsError, match="not a plain file name"):
        rv.crlite_records(changeset(records))


def test_the_name_refused_is_the_one_the_generate_mode_gives_the_full_filter():
    from invisible_core import _security_state_generate as gen

    assert rv.ENGINE_FILTER_NAME == gen.CRLITE_FILTER_FILE_NAME


def test_two_records_with_the_same_filename_are_refused():
    one = crlite("a", 1, incremental=False, filename="same.filter")
    two = crlite("b", 2, incremental=True, filename="SAME.filter")
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset([one, two]))


@pytest.mark.parametrize("field,value", [
    ("hash", None), ("hash", "abc"), ("hash", "z" * 64), ("size", None), ("size", 0), ("size", "5"), ("size", True),
    ("location", None), ("location", ""), ("location", "/rooted"),
])
def test_a_record_without_a_usable_hash_size_or_location_is_refused(field, value):
    full = crlite("a", 1, incremental=False)
    if value is None:
        del full["attachment"][field]
    else:
        full["attachment"][field] = value
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset([full]))


def test_a_record_with_no_attachment_is_refused():
    full = crlite("a", 1, incremental=False)
    del full["attachment"]
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset([full]))


def test_an_unknown_expression_in_one_record_refuses_the_whole_collection():
    records = [crlite("a", 1, incremental=False), crlite("b", 2, incremental=True, expr="env.channel == 'beta'")]
    with pytest.raises(rv.RevocationsError):
        rv.crlite_records(changeset(records))


# --- downloading the filters -----------------------------------------------------------------------------------------------------------------------------

def small_set():
    return [
        crlite("c", 3, incremental=True),
        crlite("a", 1, incremental=False),
        crlite("b", 2, incremental=True),
    ]


def test_the_filters_are_downloaded_verified_written_and_described_by_the_manifest(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    manifest = rv.fetch_crlite(tmp_path, changeset(records), BASE, reuse=no_reuse, attempts=1, updated_utc=UTC)
    full = records[1]["attachment"]
    d1, d2 = records[2]["attachment"], records[0]["attachment"]
    assert manifest == {
        "format": 1,
        "collection": "cert-revocations",
        "channel": "default",
        "collection_timestamp": 1794348206673,
        "updated_utc": UTC,
        "full": {"file": full["filename"], "sha256": full["hash"], "size": full["size"]},
        "deltas": [
            {"file": d1["filename"], "sha256": d1["hash"], "size": d1["size"]},
            {"file": d2["filename"], "sha256": d2["hash"], "size": d2["size"]},
        ],
    }
    written = (tmp_path / CRLITE_FILE_NAME).read_bytes()
    assert written == json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    assert b"\n" not in written and b" " not in written
    assert (tmp_path / full["filename"]).read_bytes() == payload(1)
    assert (tmp_path / d1["filename"]).read_bytes() == payload(2)
    assert (tmp_path / d2["filename"]).read_bytes() == payload(3)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([CRLITE_FILE_NAME, full["filename"], d1["filename"], d2["filename"]])
    assert sorted(urls_of_attachments(mozilla)) == sorted(BASE + r["attachment"]["location"] for r in records)


def test_the_manifest_bytes_for_a_small_fixture(tmp_path, mozilla):
    full = crlite("a", 1, incremental=False, filename="f.filter")
    delta = crlite("b", 2, incremental=True, filename="d.delta")
    serve(mozilla, [full, delta])
    rv.fetch_crlite(tmp_path, changeset([delta, full], timestamp=42), BASE, reuse=no_reuse, attempts=1, updated_utc=UTC)
    expected = (
        '{"format":1,"collection":"cert-revocations","channel":"default","collection_timestamp":42,"updated_utc":"%s",'
        '"full":{"file":"f.filter","sha256":"%s","size":%d},"deltas":[{"file":"d.delta","sha256":"%s","size":%d}]}'
        % (UTC, hashlib.sha256(payload(1)).hexdigest(), len(payload(1)), hashlib.sha256(payload(2)).hexdigest(), len(payload(2)))
    )
    assert (tmp_path / CRLITE_FILE_NAME).read_bytes() == expected.encode("utf-8")


def test_an_attachment_with_the_wrong_sha256_refuses_the_download_and_leaves_no_manifest(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    mozilla.answers[BASE + records[2]["attachment"]["location"]] = b"x" * len(payload(2))   # same size, other bytes
    with pytest.raises(rv.RevocationsError):
        rv.fetch_crlite(tmp_path, changeset(records), BASE, reuse=no_reuse, attempts=1, updated_utc=UTC)
    assert not (tmp_path / CRLITE_FILE_NAME).exists()


def test_an_attachment_with_the_wrong_size_refuses_the_download(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    records[0]["attachment"]["size"] += 1
    with pytest.raises(rv.RevocationsError):
        rv.fetch_crlite(tmp_path, changeset(records), BASE, reuse=no_reuse, attempts=1, updated_utc=UTC)
    assert not (tmp_path / CRLITE_FILE_NAME).exists()


def test_the_transient_failure_of_an_attachment_is_asked_again_and_a_permanent_one_is_not(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    mozilla.failures = [requests.ConnectionError("reset")]
    rv.fetch_crlite(tmp_path, changeset(records), BASE, reuse=no_reuse, attempts=3, updated_utc=UTC)
    assert len(urls_of_attachments(mozilla)) == len(records) + 1
    mozilla.calls.clear()
    mozilla.failures = [ValueError("not a transport failure")]
    (tmp_path / "again").mkdir()
    with pytest.raises(ValueError):
        rv.fetch_crlite(tmp_path / "again", changeset(records), BASE, reuse=no_reuse, attempts=3, updated_utc=UTC)
    assert len(urls_of_attachments(mozilla)) == 1


def test_a_file_the_caller_holds_is_copied_and_the_network_is_not_asked_for_it(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    held_dir = tmp_path / "held"
    held_dir.mkdir()
    held = held_dir / "old-name.bin"
    held.write_bytes(payload(2))
    asked = []

    def reuse(sha):
        asked.append(sha)
        return held if sha == hashlib.sha256(payload(2)).hexdigest() else None

    out = tmp_path / "out"
    out.mkdir()
    rv.fetch_crlite(out, changeset(records), BASE, reuse=reuse, attempts=1, updated_utc=UTC)
    reused = records[2]["attachment"]
    assert BASE + reused["location"] not in mozilla.calls
    assert sorted(urls_of_attachments(mozilla)) == sorted(BASE + r["attachment"]["location"] for r in records if r is not records[2])
    target = out / reused["filename"]
    assert target.read_bytes() == payload(2)
    assert not os.path.samefile(target, held)          # a copy, never a link
    assert held.read_bytes() == payload(2)
    assert sorted(asked) == sorted(r["attachment"]["hash"] for r in records)


def _wrong_held_file(tmp_path, mozilla, content):
    records = small_set()
    serve(mozilla, records)
    held = tmp_path / "held.bin"
    bad = content
    held.write_bytes(bad)
    out = tmp_path / "out"
    out.mkdir()
    wanted = records[2]["attachment"]["hash"]
    manifest = rv.fetch_crlite(out, changeset(records), BASE, reuse=lambda sha: held if sha == wanted else None, attempts=1, updated_utc=UTC)
    return records, held, out, manifest, bad


def test_a_held_file_with_the_wrong_content_is_ignored_and_the_attachment_is_downloaded(tmp_path, mozilla):
    records, held, out, manifest, bad = _wrong_held_file(tmp_path, mozilla, content=b"y" * len(payload(2)))
    assert BASE + records[2]["attachment"]["location"] in mozilla.calls
    assert (out / records[2]["attachment"]["filename"]).read_bytes() == payload(2)
    assert held.read_bytes() == bad          # the held file is not touched
    assert (out / CRLITE_FILE_NAME).is_file()
    assert manifest["deltas"][0]["sha256"] == hashlib.sha256(payload(2)).hexdigest()


def test_a_held_file_of_the_wrong_size_is_ignored_and_the_attachment_is_downloaded(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    held = tmp_path / "held.bin"
    held.write_bytes(payload(2) + b"extra")   # the record's hash is the real one, the file is longer
    out = tmp_path / "out"
    out.mkdir()
    wanted = records[2]["attachment"]["hash"]
    rv.fetch_crlite(out, changeset(records), BASE, reuse=lambda sha: held if sha == wanted else None, attempts=1, updated_utc=UTC)
    assert BASE + records[2]["attachment"]["location"] in mozilla.calls
    assert (out / records[2]["attachment"]["filename"]).read_bytes() == payload(2)
    assert held.read_bytes() == payload(2) + b"extra"


def test_a_held_file_that_cannot_be_read_is_ignored(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    out = tmp_path / "out"
    out.mkdir()
    gone = tmp_path / "gone.bin"
    wanted = records[2]["attachment"]["hash"]
    rv.fetch_crlite(out, changeset(records), BASE, reuse=lambda sha: gone if sha == wanted else None, attempts=1, updated_utc=UTC)
    assert BASE + records[2]["attachment"]["location"] in mozilla.calls
    assert (out / records[2]["attachment"]["filename"]).read_bytes() == payload(2)


def test_when_the_download_of_an_ignored_held_file_is_wrong_too_the_download_is_refused(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    mozilla.answers[BASE + records[2]["attachment"]["location"]] = b"z" * len(payload(2))
    held = tmp_path / "held.bin"
    held.write_bytes(b"y" * len(payload(2)))
    out = tmp_path / "out"
    out.mkdir()
    wanted = records[2]["attachment"]["hash"]
    with pytest.raises(rv.RevocationsError):
        rv.fetch_crlite(out, changeset(records), BASE, reuse=lambda sha: held if sha == wanted else None, attempts=1, updated_utc=UTC)
    assert not (out / CRLITE_FILE_NAME).exists()


def test_a_bad_updated_utc_is_refused(tmp_path, mozilla):
    records = small_set()
    serve(mozilla, records)
    with pytest.raises(rv.RevocationsError):
        rv.fetch_crlite(tmp_path, changeset(records), BASE, reuse=no_reuse, attempts=1, updated_utc="yesterday")
    assert mozilla.calls == []


# --- the changeset ---------------------------------------------------------------------------------------------------------------------------------------

def test_the_changeset_is_asked_through_the_seam_with_the_collection_and_the_expected_timestamp(mozilla):
    url = ("https://firefox.settings.services.mozilla.com/v2/buckets/security-state/collections/onecrl/changeset?_expected=77")
    mozilla.answers[url] = b'{"timestamp":77,"metadata":{},"changes":[]}'
    assert rv.fetch_changeset("onecrl", 77, 1) == {"timestamp": 77, "metadata": {}, "changes": []}
    assert mozilla.calls == [url]


def test_a_changeset_that_is_not_an_object_is_refused(mozilla):
    url = ("https://firefox.settings.services.mozilla.com/v2/buckets/security-state/collections/onecrl/changeset?_expected=0")
    mozilla.answers[url] = b"[1]"
    with pytest.raises(rv.RevocationsError):
        rv.fetch_changeset("onecrl", 0, 1)


# --- OneCRL ----------------------------------------------------------------------------------------------------------------------------------------------

def onecrl_issuer(rid: str, enabled=False) -> dict:
    return {"id": rid, "enabled": enabled, "issuerName": "TUZZeA==", "serialNumber": "AMvc+g1kEScJzxS35IWCUA==", "details": {"who": "x"},
            "last_modified": 5, "schema": 1}


def onecrl_subject(rid: str) -> dict:
    return {"id": rid, "enabled": True, "subject": "c3ViamVjdA==", "pubKeyHash": "aGFzaA==", "last_modified": 6, "schema": 1}


def test_onecrl_keeps_the_disabled_records_and_both_forms_in_id_order():
    records = [onecrl_subject("c"), onecrl_issuer("b", enabled=False), onecrl_issuer("a", enabled=True)]
    listing = rv.build_onecrl(changeset(records, timestamp=99), updated_utc=UTC)
    assert listing == {
        "format": 1,
        "collection": "onecrl",
        "collection_timestamp": 99,
        "updated_utc": UTC,
        "revocations": [
            {"issuerName": "TUZZeA==", "serialNumber": "AMvc+g1kEScJzxS35IWCUA=="},
            {"issuerName": "TUZZeA==", "serialNumber": "AMvc+g1kEScJzxS35IWCUA=="},
            {"subject": "c3ViamVjdA==", "pubKeyHash": "aGFzaA=="},
        ],
    }


def test_onecrl_issuer_and_serial_win_over_subject_and_hash():
    both = dict(onecrl_issuer("a"), subject="c3ViamVjdA==", pubKeyHash="aGFzaA==")
    listing = rv.build_onecrl(changeset([both]), updated_utc=UTC)
    assert listing["revocations"] == [{"issuerName": "TUZZeA==", "serialNumber": "AMvc+g1kEScJzxS35IWCUA=="}]


def test_onecrl_skips_a_record_with_neither_pair_as_retail_does():
    half = {"id": "h", "issuerName": "TUZZeA==", "subject": "c3ViamVjdA=="}
    empty = dict(onecrl_issuer("e"), serialNumber="")
    listing = rv.build_onecrl(changeset([half, empty, onecrl_subject("s")]), updated_utc=UTC)
    assert listing["revocations"] == [{"subject": "c3ViamVjdA==", "pubKeyHash": "aGFzaA=="}]


def test_onecrl_drops_deleted_records():
    listing = rv.build_onecrl(changeset([dict(onecrl_issuer("a"), deleted=True), onecrl_subject("b")]), updated_utc=UTC)
    assert len(listing["revocations"]) == 1


@pytest.mark.parametrize("bad", ["not base64!", "TUZZeA", "TUZZ eA==", "TUZZeA===", 5])
def test_onecrl_refuses_a_value_that_is_not_strict_base64(bad):
    record = onecrl_issuer("a")
    record["issuerName"] = bad
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl(changeset([record, onecrl_subject("b")]), updated_utc=UTC)
    record = onecrl_subject("a")
    record["pubKeyHash"] = bad
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl(changeset([record]), updated_utc=UTC)


@pytest.mark.parametrize("timestamp", [None, 0, -1, "5", True, 1.5])
def test_onecrl_refuses_a_missing_or_invalid_timestamp(timestamp):
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl({"timestamp": timestamp, "changes": [onecrl_issuer("a")]}, updated_utc=UTC)


def test_onecrl_refuses_duplicate_ids_and_an_empty_collection():
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl(changeset([onecrl_issuer("a"), onecrl_subject("a")]), updated_utc=UTC)
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl(changeset([]), updated_utc=UTC)
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl(changeset([dict(onecrl_issuer("a"), deleted=True)]), updated_utc=UTC)
    with pytest.raises(rv.RevocationsError):
        rv.build_onecrl({"timestamp": 5}, updated_utc=UTC)


def test_onecrl_json_is_written_compact(tmp_path):
    listing = rv.build_onecrl(changeset([onecrl_subject("b"), onecrl_issuer("a")], timestamp=7), updated_utc=UTC)
    path = rv.write_onecrl(tmp_path, listing)
    assert path == tmp_path / ONECRL_FILE_NAME
    assert path.read_bytes() == (
        b'{"format":1,"collection":"onecrl","collection_timestamp":7,"updated_utc":"2026-11-20T10:00:00Z","revocations":['
        b'{"issuerName":"TUZZeA==","serialNumber":"AMvc+g1kEScJzxS35IWCUA=="},{"subject":"c3ViamVjdA==","pubKeyHash":"aGFzaA=="}]}'
    )
