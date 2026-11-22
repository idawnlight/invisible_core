"""`InputLatency` is part of the public API: `from invisible_core import InputLatency`.

It used to be reachable only through `invisible_core.juggler._behaviour`, a
private module. It is re-exported, not copied, and the package import stays light:
the name loads the Juggler client on first use, not at `import invisible_core`.
"""
import subprocess
import sys

import invisible_core
from invisible_core import InputLatency
from invisible_core import juggler
from invisible_core.juggler import _behaviour


def test_input_latency_is_exported_by_the_package():
    assert "InputLatency" in invisible_core.__all__
    assert "InputLatency" in juggler.__all__


def test_it_is_the_same_object_as_the_private_one():
    assert InputLatency is _behaviour.InputLatency
    assert juggler.InputLatency is _behaviour.InputLatency


def test_its_draw_is_deterministic_and_equals_the_private_path():
    first = InputLatency.from_seed(42).draw(7)
    assert isinstance(first, float)
    assert first == InputLatency.from_seed(42).draw(7)
    assert first == _behaviour.InputLatency.from_seed(42).draw(7)


def test_importing_the_package_still_does_not_load_the_juggler_client():
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys, invisible_core; print('invisible_core.juggler' in sys.modules)"],
        capture_output=True, text=True, check=True).stdout.strip()
    assert out == "False"
