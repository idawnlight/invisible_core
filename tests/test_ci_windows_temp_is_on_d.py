r"""Every Windows job that launches a browser has TEMP and TMP on D:, set on the job.

The profile of every Firefox the tests launch is made in TEMP. On the Windows runners of GitHub the default TEMP is on C:, and four browsers at
once saturate that disk (a queue up to 144, latencies up to 4 s): the parent's main thread stays still 40-60 s and the e2e fail at random
(a `goto` that hangs, a start that never answers). Measured on 20/11 with two hunts: the profiles on C: took 5 of 4 shards, TEMP and TMP on
`D:\a\_temp` took none. A test cannot fail for a reason that is not its own, so the fix is at the source: the job's `env` names D:.

`runner.temp` is not readable in a job's `env` (only `github`, `needs`, `strategy`, `matrix`, `inputs`, `secrets` and `vars` are), so the job
names the runner's temp folder itself: `D:\a\_temp`, which the runner makes before the first step. A job that runs on both systems says
`startsWith(<where it runs>, 'windows') && 'D:\a\_temp' || '/tmp'` (`/tmp` is what Linux uses anyway).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
BS = chr(92)
D_TEMP = "D:" + BS + "a" + BS + "_temp"

#: A Windows job that is left alone, and why. Nothing else is.
EXEMPT = {
    ("ci.yml", "msix-host"): "one engine started INSIDE an MSIX package, where the package's own virtualisation of the profile is what the job measures",
    ("ci.yml", "arm64-host"): "one engine on a windows-11-arm runner, whose volumes are not the ones of the x64 runners; one browser, no disk contention",
}

CONDITIONAL = re.compile(
    r"^\$\{\{\s*startsWith\((?P<ctx>(?:matrix|inputs)\.\w+),\s*'windows'\)\s*&&\s*'(?P<win>[^']*)'\s*\|\|\s*'(?P<other>[^']*)'\s*\}\}$")
CONTEXT = re.compile(r"\$\{\{\s*((?:matrix|inputs)\.\w+)\s*\}\}")


def _legs(spec: dict, job: dict) -> list[dict]:
    """The contexts a job runs in: one dict `{"matrix.os": "windows-latest", ...}` per leg (one empty dict when the job has no matrix)."""
    matrix = dict(((job.get("strategy") or {}).get("matrix")) or {})
    include = matrix.pop("include", None) or []
    exclude = matrix.pop("exclude", None) or []
    legs = [{}]
    for key, values in matrix.items():
        legs = [dict(leg, **{"matrix." + key: v}) for leg in legs for v in values]
    legs = [leg for leg in legs if not any(all(leg.get("matrix." + k) == v for k, v in ex.items()) for ex in exclude)]
    rows = [{"matrix." + k: v for k, v in row.items()} for row in include]
    legs = rows if (rows and not matrix) else legs + rows
    on = spec.get("on", spec.get(True)) or {}
    for name, cfg in ((on.get("workflow_dispatch") or {}).get("inputs") or {}).items():
        if (cfg or {}).get("options"):
            legs = [dict(leg, **{"inputs." + name: o}) for leg in legs for o in cfg["options"]]
    return legs


def _runs_on(leg: dict, expr) -> str:
    return CONTEXT.sub(lambda m: str(leg.get(m.group(1), "?")), str(expr))


def _value(leg: dict, raw) -> str:
    """What a job's env value is on one leg: a literal, or the one conditional the workflows use."""
    raw = str(raw)
    m = CONDITIONAL.match(raw.strip())
    if not m:
        return raw
    return m.group("win") if str(leg.get(m.group("ctx"), "")).startswith("windows") else m.group("other")


def windows_jobs_without_temp_on_d(name: str, spec: dict) -> list[str]:
    """One line per Windows leg of the workflow whose TEMP or TMP is not on D:."""
    problems = []
    for job_id, job in (spec.get("jobs") or {}).items():
        if "runs-on" not in job or (name, job_id) in EXEMPT:
            continue
        env = job.get("env") or {}
        for leg in _legs(spec, job):
            runner = _runs_on(leg, job["runs-on"])
            if "windows" not in runner:
                continue
            for var in ("TEMP", "TMP"):
                value = _value(leg, env[var]) if var in env else None
                if value is None or not value.upper().startswith("D:" + BS):
                    problems.append("%s: job `%s` on %s has %s=%r, not a folder on D:" % (name, job_id, runner, var, value))
    return problems


def _workflows():
    return sorted(WORKFLOWS.glob("*.yml"))


@pytest.mark.parametrize("path", _workflows(), ids=lambda p: p.name)
def test_every_windows_job_keeps_the_profiles_on_d(path):
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert windows_jobs_without_temp_on_d(path.name, spec) == []


def test_the_exempt_jobs_exist_and_run_on_windows():
    for file, job in EXEMPT:
        spec = yaml.safe_load((WORKFLOWS / file).read_text(encoding="utf-8"))
        assert "windows" in str(spec["jobs"][job]["runs-on"]), "%s/%s is exempt but is not a Windows job any more: drop the exemption" % (file, job)


def _job(runs_on, env=None, strategy=None):
    return {"jobs": {"a": {"runs-on": runs_on, "env": env, "strategy": strategy, "steps": []}}}


def test_the_check_sees_what_it_is_meant_to_see():
    """A check that has only ever said fine is not known to say anything else."""
    check = windows_jobs_without_temp_on_d
    assert check("x.yml", _job("windows-2022")), "a Windows job with no TEMP passed"
    assert len(check("x.yml", _job("windows-2022", {"TEMP": "C:" + BS + "t", "TMP": D_TEMP}))) == 1, "TEMP on C: passed"
    assert len(check("x.yml", _job("windows-2022", {"TEMP": D_TEMP}))) == 1, "a job with TEMP and no TMP passed"
    assert check("x.yml", _job("windows-2022", {"TEMP": D_TEMP, "TMP": D_TEMP})) == []
    cond = "${{ startsWith(matrix.os, 'windows') && '" + D_TEMP + "' || '/tmp' }}"
    matrix = {"matrix": {"os": ["ubuntu-24.04", "windows-latest"]}}
    assert check("x.yml", _job("${{ matrix.os }}", {"TEMP": cond, "TMP": cond}, matrix)) == []
    wrong_way = cond.replace("'" + D_TEMP + "' || '/tmp'", "'/tmp' || '" + D_TEMP + "'")
    assert len(check("x.yml", _job("${{ matrix.os }}", {"TEMP": wrong_way, "TMP": wrong_way}, matrix))) == 2, "a matrix job that is on C: on Windows passed"
    include = {"matrix": {"include": [{"os": "linux", "runner": "ubuntu-24.04"}, {"os": "windows", "runner": "windows-2022"}]}}
    assert len(check("x.yml", _job("${{ matrix.runner }}", None, include))) == 2, "a Windows leg of an `include` matrix was not seen"
    assert check("x.yml", _job("ubuntu-24.04")) == [], "a Linux job was judged"
