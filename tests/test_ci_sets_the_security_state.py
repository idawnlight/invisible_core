"""Every job of ci.yml launches with the fixed security state of this repository, so the core's CI asks Mozilla for nothing and runs no generation.

Without STEALTHFOX_SECURITY_STATE the core downloads Mozilla's three collections on a cold cache (the first `write_user_js` of a runner) and has the engine generate cert_storage
from them; a gate that depends on a site it does not control can go red for reasons that are not the code's. ci.yml sets the variable once, at the top, to ci/security-state
(a result with no data and no `security_state/` directory, its sha256 in ci/security-state.pin.json): every job sees it, wrapper-on-this-core included, which runs the wrapper's
MAIN against this core. user-install.yml proves what a user gets and is left alone.
"""
import hashlib
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
LINE = "  STEALTHFOX_SECURITY_STATE: ${{ github.workspace }}/ci/security-state\n"


def test_the_workflow_sets_the_fixed_state_once_for_every_job():
    text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    assert text.count("STEALTHFOX_SECURITY_STATE") == 1, "ci.yml names the variable more or less than once"
    top = text[:text.index("\njobs:\n")]
    assert LINE in top, "the variable is not in the workflow's own env, so some job launches without it"


def test_the_fixed_state_is_the_pinned_one_and_has_no_data():
    pin = json.loads((ROOT / "ci" / "security-state.pin.json").read_text(encoding="utf-8"))
    raw = (ROOT / pin["file"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == pin["sha256"] and len(raw) == pin["bytes"]
    assert (ROOT / pin["file"]).parent == ROOT / "ci" / "security-state"
    result = json.loads(raw)
    assert result["format"] == 1 and result["ok"] is True and result["error"] is None
    assert result["crlite_filter_hashes"] == []
    assert result["engine"] == {"version": "", "build_id": ""}
    assert [c["collection_timestamp"] for c in result["collections"].values()] == [0, 0, 0]
    assert sorted(p.name for p in (ROOT / "ci" / "security-state").iterdir()) == ["securitystate-result.json"], (
        "a security_state/ directory would be copied into every CI profile")


def test_the_workflow_that_proves_the_installation_is_left_alone():
    assert "STEALTHFOX_SECURITY_STATE" not in (WORKFLOWS / "user-install.yml").read_text(encoding="utf-8")
