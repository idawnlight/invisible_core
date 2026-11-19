"""The clients' e2e run reruns nothing and writes a junit for every pass.

The run used to pass `--reruns 2 --only-rerun <transient messages>`: a test red
at its first attempt was green at its second and the error of the first was
thrown away (`-v --tb=short` prints only `RERUN`). In the wrapper's run
43763144152 two tests were green with no error anywhere to read. A test that
passes at its second attempt is not green.

Known bad, each tried against this file: the old command (rerun options in it)
fails the unit test and makes the flaky test below green; dropping
`-p no:rerunfailures` lets the `reruns = 2` of the suite's own ini file turn
the retries back on, and the run goes green.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

# The plugin is installed in the dev environment on purpose: the run must
# refuse it, and that is only a test if it could have been used.
import pytest_rerunfailures  # noqa: F401
import pytest_timeout  # noqa: F401
import xdist  # noqa: F401

from invisible_core.testing.e2e import (JUNIT_DIR_ENV, command, junit_dir,
                                        junit_file, passes)


@pytest.mark.unit
@pytest.mark.parametrize("procs", ["1", "4"])
def test_the_command_has_no_rerun_option_and_refuses_the_plugin(procs, tmp_path):
    for width, selection in passes(procs):
        cmd = command(width, [], selection=selection,
                      junit=junit_file(tmp_path, selection))
        rerun_options = [a for a in cmd if a.startswith("-")
                         and "rerun" in a.split("=")[0]]
        assert rerun_options == [], cmd
        pairs = [cmd[i:i + 2] for i in range(len(cmd))]
        assert ["-p", "no:rerunfailures"] in pairs, cmd
        assert ["-o", "junit_family=xunit2"] in pairs, cmd
        assert any(a.startswith("--junitxml=") for a in cmd), cmd


@pytest.mark.unit
def test_two_passes_write_two_files(tmp_path):
    files = {junit_file(tmp_path, selection) for _, selection in passes("4")}
    assert len(files) == 2, files
    default = {a for w, s in passes("4") for a in command(w, [], selection=s)
               if a.startswith("--junitxml=")}
    assert len(default) == 2, default


@pytest.mark.unit
def test_the_junit_goes_where_the_caller_says_then_beside_the_watchdog_log(tmp_path):
    repo = tmp_path / "repo"
    assert junit_dir(repo, {}) == repo / "e2e-junit"
    assert junit_dir(repo, {"INVPW_TEST_WATCHDOG_FILE": str(tmp_path / "t" / "w.log")}) == tmp_path / "t"
    assert junit_dir(repo, {"INVPW_TEST_WATCHDOG_FILE": str(tmp_path / "t" / "w.log"),
                            JUNIT_DIR_ENV: str(tmp_path / "j")}) == tmp_path / "j"


_FILES = {
    # the suite's own ini file asks for the retries: the run must not honour it
    "pytest.ini": """
        [pytest]
        markers =
            e2e: opens the browser
            wall_clock: its verdict reads a wall-clock duration
        reruns = 2
    """,
    "test_flaky.py": """
        from pathlib import Path

        import pytest

        pytestmark = pytest.mark.e2e


        def test_fails_at_its_first_attempt_only():
            seen = Path(__file__).with_name("attempted")
            first = not seen.exists()
            seen.write_text("x")
            assert not first, "context was destroyed: the first attempt"
    """,
    "test_other.py": """
        import pytest

        pytestmark = pytest.mark.e2e


        def test_other():
            pass
    """,
    "test_timed.py": """
        import pytest

        pytestmark = [pytest.mark.e2e, pytest.mark.wall_clock]


        def test_timed():
            pass
    """,
}

_ENTRY = (
    "import sys\n"
    "from pathlib import Path\n"
    "from invisible_core.testing.e2e import main\n"
    "sys.exit(main(sys.argv[1:-1], repo=Path(sys.argv[-1]), deadline_s=60))\n")


@pytest.mark.integration
def test_a_test_red_at_its_first_attempt_is_a_red_run_with_its_error_in_the_junit(tmp_path):
    suite = tmp_path / "suite"
    suite.mkdir()
    for name, body in _FILES.items():
        (suite / name).write_bytes(textwrap.dedent(body).lstrip().encode())
    binary = tmp_path / "firefox"
    binary.write_bytes(b"")
    out = tmp_path / "out"
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST_XDIST")}
    env[JUNIT_DIR_ENV] = str(out)
    proc = subprocess.run(
        [sys.executable, "-c", _ENTRY, str(binary), "-n", "2", str(suite)],
        capture_output=True, timeout=180, env=env)
    log = (proc.stdout + proc.stderr).decode(errors="replace")
    assert proc.returncode == 1, log[-3000:]
    assert "RERUN" not in log, log[-3000:]
    written = sorted(Path(out).glob("*.xml"))
    assert len(written) == 2, (written, log[-3000:])
    failures = [f for p in written for f in ET.parse(p).getroot().iter("failure")]
    assert len(failures) == 1, log[-3000:]
    assert "context was destroyed: the first attempt" in (failures[0].get("message") or ""), failures[0].attrib
