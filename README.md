# Invisible Core for Firefox 159

This branch pairs `invisible_core 159.49.0` with the local Firefox 159.0
implementation and `invisible_playwright 0.43.1.dev0`.

The core generates session profiles and Firefox preferences, owns the shared
Juggler protocol client, starts and tracks browser processes, and verifies the
engine against `src/invisible_core/seal.json`.

Install the paired core and Playwright checkouts into the same environment:

```sh
python -m pip install -e /path/to/invisible_core -e /path/to/invisible_playwright
```

For this local build, pass `binary_path` to `InvisiblePlaywright`. The seal
records the Firefox version, BuildID and engine Git commit. Generate it with
the engine's `scripts/make_seal.py --from-tree`, then update the exact core
dependency in the wrapper.

For published archives, generate a seal with asset names, hashes, sizes and
per-platform BuildIDs. `INVISIBLE_FIREFOX_RELEASE_REPOSITORY=owner/repository`
selects the GitHub repository used by both release downloads and API lookup.

`invisible-core doctor` reports the package and engine pair. The existing
unit, integration and browser tests live under `tests/`; source contracts
inspect the engine commit recorded in the seal. Sibling repository checks
select worktrees on the same branch.

The package's original code is MIT. Its shared Juggler client retains the
licenses recorded alongside the source.
