"""Every job of ci.yml launches with the fixed intermediates list of this repository, so the core's CI asks Mozilla for nothing.

Without STEALTHFOX_INTERMEDIATES the core downloads Mozilla's list on a cold cache (the first `write_user_js` of a runner) and checks it once a week; a gate that
depends on a site it does not control can go red for reasons that are not the code's. ci.yml sets the variable once, at the top, to ci/intermediates.json
(empty, format 1, its sha256 in ci/intermediates.pin.json): every job sees it, wrapper-on-this-core included, which runs the wrapper's MAIN against this core.
user-install.yml proves what a user gets and is left alone.
"""
import hashlib
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
LINE = "  STEALTHFOX_INTERMEDIATES: ${{ github.workspace }}/ci/intermediates.json\n"


def test_the_workflow_sets_the_fixed_list_once_for_every_job():
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert text.count("STEALTHFOX_INTERMEDIATES") == 1, "ci.yml names the variable more or less than once"
    top = text[:text.index("\njobs:\n")]
    assert LINE in top, "the variable is not in the workflow's own env, so some job launches without it"


def test_the_fixed_list_is_the_pinned_one_and_is_valid():
    pin = json.loads((ROOT / "ci" / "intermediates.pin.json").read_text(encoding="utf-8"))
    raw = (ROOT / pin["file"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == pin["sha256"] and len(raw) == pin["bytes"]
    listing = json.loads(raw)
    assert listing["format"] == 1 and listing["count"] == len(listing["certs"]) == 0
    assert listing["set_sha256"] == hashlib.sha256(b"").hexdigest()


def test_the_workflow_that_proves_the_installation_is_left_alone():
    assert "STEALTHFOX_INTERMEDIATES" not in (WORKFLOWS / "user-install.yml").read_text(encoding="utf-8")
