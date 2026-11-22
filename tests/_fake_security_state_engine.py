"""A stand-in for the engine's security-state GENERATE MODE, a standalone script: `python -I _fake_security_state_engine.py <the caller's launch line> -profile <dir>`.

It respects the contract of `invisible_core._security_state_generate` exactly. It PRINTS NOTHING: the outcome is the exit code and `securitystate-result.json` (with `"ok": false` and
an `"error"` text on a failure). It refuses (exit 2, the result written when the profile directory exists) whatever the core must not do: other arguments than EXACTLY the expected launch line
(`FAKE_ENGINE_EXPECT_ARGS`, a JSON list of the arguments after the script; unset: `["-headless", "-no-remote"]`) followed by `-profile <dir>`, a work profile that holds anything but `user.js`, a `user.js` that is not exactly the four prefs (generate = true, three absolute paths of files that exist), and a
per-user variable (`XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `APPDATA`, `LOCALAPPDATA`) that is not set, not an absolute path, not an existing directory, not inside the parent of
the profile directory, or inside the profile itself.

Then it reads the three inputs and leaves `security_state/` and `securitystate-result.json` in the profile. Its identity is `FAKE_ENGINE_VERSION` / `FAKE_ENGINE_BUILD_ID`; its
behaviour is `FAKE_ENGINE_MODE`: ok (default), exit1 (result ok false with an error, exit 1), nowrite (exit 3, no result at all), noresult (exit 0, no result), badjson, wrongbuild,
wronghashes, wrongtimestamp, nofilter, hang, noisy (prints to stdout and stderr, then succeeds), envdump (succeeds, the four variables as it saw them under the extra key `env`).
`hang` starts a child that also sleeps and then sleeps itself; the pids go to the profile (`hang.pids`) and, when `FAKE_ENGINE_PIDFILE` is set, to that file (the profile is
deleted by the core, so a test reads them there).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

PREFS = ("zoom.stealth.securitystate.generate", "zoom.stealth.intermediates.file", "zoom.stealth.onecrl.file", "zoom.stealth.crlite.file")
LINE = re.compile(r'^user_pref\(("(?:[^"\\]|\\.)*"), (true|false|"(?:[^"\\]|\\.)*"|-?\d+)\);$')


RESULT_NAME = "securitystate-result.json"
HOME_VARIABLES = ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "APPDATA", "LOCALAPPDATA")
PROFILE = None


def fail(code, message):
    """The only way out of a failure: the result with ok false and the error (when the profile directory exists), and the exit code. Nothing is printed."""
    if PROFILE and os.path.isdir(PROFILE):
        with open(os.path.join(PROFILE, RESULT_NAME), "w", encoding="utf-8") as f:
            json.dump({"format": 1, "ok": False, "error": "fake engine: " + message}, f)
    sys.exit(code)


def refuse(message):
    fail(2, message)


def inside(path, parent):
    path, parent = os.path.realpath(path), os.path.realpath(parent)
    try:
        return os.path.commonpath([path, parent]) == parent and path != parent
    except ValueError:  # another drive
        return False


def check_home_directories(profile):
    parent = os.path.dirname(os.path.realpath(profile))
    for name in HOME_VARIABLES:
        value = os.environ.get(name)
        if not value:
            refuse("%s is not set" % name)
        if not os.path.isabs(value):
            refuse("%s is %r: not an absolute path" % (name, value))
        if not os.path.isdir(value):
            refuse("%s is %r: not an existing directory" % (name, value))
        if not inside(value, parent):
            refuse("%s is %r: not inside %r, the directory that holds the profile" % (name, value, parent))
        if os.path.realpath(value) == os.path.realpath(profile) or inside(value, profile):
            refuse("%s is %r: inside the profile" % (name, value))


def read_prefs(profile):
    raw = open(os.path.join(profile, "user.js"), "rb").read()
    if b"\r" in raw or not raw.endswith(b"\n"):
        refuse("user.js is not LF lines ending in a newline")
    prefs = {}
    order = []
    for line in raw.decode("utf-8").split("\n")[:-1]:
        m = LINE.match(line)
        if not m:
            refuse("user.js has a line that is not a user_pref: %r" % line)
        name = json.loads(m.group(1))
        prefs[name] = json.loads(m.group(2))
        order.append(name)
    if order != list(PREFS):
        refuse("user.js holds %r, the contract is exactly %r" % (order, list(PREFS)))
    return prefs


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    args = sys.argv[1:]
    expected = json.loads(os.environ.get("FAKE_ENGINE_EXPECT_ARGS", '["-headless", "-no-remote"]'))
    global PROFILE
    # The profile is the last argument, so that a refusal can still leave its result there.
    if len(args) >= 2 and args[-2] == "-profile":
        PROFILE = args[-1]
    if len(args) != len(expected) + 2 or args[:-2] != expected or args[-2] != "-profile":
        refuse("arguments are %r, the contract is exactly %r + -profile <dir>" % (args, expected))
    profile = args[-1]
    if not os.path.isabs(profile) or not os.path.isdir(profile):
        refuse("the profile %r is not an existing absolute directory" % profile)
    if sorted(os.listdir(profile)) != ["user.js"]:
        refuse("the work profile holds %r, it must hold only user.js" % sorted(os.listdir(profile)))
    prefs = read_prefs(profile)
    check_home_directories(profile)
    if prefs[PREFS[0]] is not True:
        refuse("%s is %r, not true" % (PREFS[0], prefs[PREFS[0]]))
    for name in PREFS[1:]:
        v = prefs[name]
        if not isinstance(v, str) or not os.path.isabs(v) or not os.path.isfile(v):
            refuse("%s is %r: not the absolute path of an existing file" % (name, v))

    mode = os.environ.get("FAKE_ENGINE_MODE", "ok")
    build_id = os.environ.get("FAKE_ENGINE_BUILD_ID", "20261119174916")
    version = os.environ.get("FAKE_ENGINE_VERSION", "159.0")

    if mode == "hang":
        child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(3600)"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pids = "%d\n%d\n" % (os.getpid(), child.pid)
        open(os.path.join(profile, "hang.pids"), "w").write(pids)
        pidfile = os.environ.get("FAKE_ENGINE_PIDFILE")
        if pidfile:
            open(pidfile, "w").write(pids)
        time.sleep(3600)
        return 0
    if mode == "exit1":
        fail(1, "cert_storage refused the import")
    if mode == "nowrite":
        return 3
    if mode == "noisy":
        sys.stdout.write("noise on stdout " * 100000)
        sys.stdout.flush()
        sys.stderr.write("noise on stderr " * 100000)
        sys.stderr.flush()

    inter_path, onecrl_path, crlite_path = (prefs[n] for n in PREFS[1:])
    inter_bytes = open(inter_path, "rb").read()
    onecrl_bytes = open(onecrl_path, "rb").read()
    crlite_bytes = open(crlite_path, "rb").read()
    inter, onecrl, crlite = json.loads(inter_bytes), json.loads(onecrl_bytes), json.loads(crlite_bytes)
    beside = os.path.dirname(crlite_path)
    parts = [crlite["full"]] + list(crlite.get("deltas") or [])
    files = {}
    for part in parts:
        files[part["file"]] = open(os.path.join(beside, part["file"]), "rb").read()

    state = os.path.join(profile, "security_state")
    os.mkdir(state)
    open(os.path.join(state, "data.safe.bin"), "wb").write(hashlib.sha256(inter_bytes + onecrl_bytes + crlite_bytes).digest())
    if mode != "nofilter":
        open(os.path.join(state, "crlite.filter"), "wb").write(files[crlite["full"]["file"]])
    for part in crlite.get("deltas") or []:
        open(os.path.join(state, part["file"]), "wb").write(files[part["file"]])

    hashes = [sha256(files[p["file"]]) for p in parts]
    if mode == "wronghashes":
        hashes = hashes[:-1]
    stamps = {"intermediates": inter["collection_timestamp"], "onecrl": onecrl["collection_timestamp"], "cert-revocations": crlite["collection_timestamp"]}
    if mode == "wrongtimestamp":
        stamps["onecrl"] += 1
    result = {
        "format": 1,
        "ok": True,
        "error": None,
        "engine": {"version": version, "build_id": "19990101000000" if mode == "wrongbuild" else build_id},
        "collections": {
            "intermediates": {"collection_timestamp": stamps["intermediates"]},
            "onecrl": {"collection_timestamp": stamps["onecrl"]},
            "cert-revocations": {"collection_timestamp": stamps["cert-revocations"], "channel": "default"},
        },
        "crlite_filter_hashes": hashes,
    }
    if mode == "envdump":
        result["env"] = {name: os.environ.get(name) for name in HOME_VARIABLES}
    if mode == "noresult":
        return 0
    with open(os.path.join(profile, "securitystate-result.json"), "w", encoding="utf-8") as f:
        f.write("{not json" if mode == "badjson" else json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
