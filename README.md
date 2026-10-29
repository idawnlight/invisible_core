# Invisible Core

This fork supplies the profile generator, Firefox preferences, shared Juggler
client, browser process management, and engine installer used by
[invisible_playwright](https://github.com/idawnlight/invisible_playwright).

The current pair is `invisible_core 159.49.1` and
`invisible_playwright 0.43.1`, using Firefox 159.0 from the native
[`firefox-159.0-r1` release](https://github.com/idawnlight/firefox_antidetect_patch/releases/tag/firefox-159.0-r1).
This release provides **Linux x86_64** binaries. Python 3.11 or newer and Git
are required.

Install both Python packages from their Git tags in one command:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install \
  "invisible-core @ git+https://github.com/idawnlight/invisible_core.git@v159.49.1" \
  "invisible-playwright @ git+https://github.com/idawnlight/invisible_playwright.git@v0.43.1"
```

Start a session normally:

```python
from invisible_playwright import InvisiblePlaywright

with InvisiblePlaywright(seed=42, headless=True) as browser:
    page = browser.new_page()
    page.goto("https://example.com")
    print(page.title())
```

The first session downloads Firefox from the fork's GitHub Release. The
bundled seal selects the exact asset and records its SHA256, Firefox version,
BuildID, and source commit. The installer checks these values and reuses the
verified cache on later starts. Applications need no local Firefox build,
`binary_path`, or release-repository environment variable.

The [installation guide](https://github.com/idawnlight/invisible_playwright/blob/main/docs/installation.md)
includes Linux runtime dependencies and installation details. To download the
engine through the core alone:

```sh
python -c 'from invisible_core import ensure_binary; print(ensure_binary())'
```

Both Python repositories use `main` and their own version tags. The native
Firefox repository maintains `release/159`; its engine tags, such as
`firefox-159.0-r1`, are independent of the Python package versions. Updating
the default bundled seal requires a new core package version and the matching
wrapper dependency pin.

For development, install the two checkouts together with `pip install -e`.
The unit and integration suites are under `tests/`; release workflows build
and check the wheel and sdist before uploading them to GitHub Releases.

The package's original code is MIT. Its shared Juggler client retains the
licenses recorded alongside the source.
