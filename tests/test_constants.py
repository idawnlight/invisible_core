# MOVED FROM invisible_playwright/tests/ ON 2026-07-27.
#
# Every test in this file exercises code in THIS package and reached it through
# a four-line back-compat shim in the wrapper. That is not where coverage for a
# module belongs, and it was not academic: measured on 2026-07-27, six realistic
# one-line breaks in core code SURVIVED the core's own suite and were caught
# only by the wrapper's - `cloak_prefs()` returning {}, SOCKS detection always
# False, the scheme never stripped from a proxy server, `_proxy_is_set` always
# True, the locale always en-US, `get_default_args()` injecting -headless. The
# core's pre-push gate and its publish gate were both green over all six.
#
# `test_no_test_reaches_the_core_through_a_shim` in the wrapper keeps them here.
from dataclasses import replace

import pytest

from invisible_core.constants import (
    ARCHIVE_NAME,
    BINARY_BASENAME,
    BINARY_VERSION,
    FIREFOX_UPSTREAM_VERSION,
    RELEASE_URL_TEMPLATE,
)
from invisible_core.seal import Asset, DEFAULT_ENTRY_REL, SUPPORTED_LEGS, active_seal


@pytest.fixture
def complete_archive_seal(monkeypatch):
    """The archive mapping supports more legs than each individual release ships."""
    import invisible_core.constants as constants

    assets = {}
    for platform, arch in SUPPORTED_LEGS:
        suffix = f"win-{arch}.zip" if platform == "win32" else f"linux-{arch}.tar.gz"
        name = f"{BINARY_BASENAME}-{suffix}"
        assets[name] = Asset(name, platform, arch, "0" * 64, 1,
                             DEFAULT_ENTRY_REL[platform], "", "20261029033851")
    monkeypatch.setattr(constants, "_SEAL", replace(constants._SEAL, assets=assets))


@pytest.mark.unit
def test_binary_version_format():
    assert BINARY_VERSION == active_seal().tag
    assert active_seal().is_release


@pytest.mark.unit
def test_archive_name_windows(complete_archive_seal):
    name = ARCHIVE_NAME("win32", "AMD64")
    assert name.endswith(".zip")
    assert "win-x86_64" in name


@pytest.mark.unit
def test_archive_name_linux():
    name = ARCHIVE_NAME("linux", "x86_64")
    assert name.endswith(".tar.gz")
    assert "linux-x86_64" in name


@pytest.mark.unit
@pytest.mark.parametrize("machine", ["arm64", "x86_64"])
def test_macos_is_refused_rather_than_forgotten(machine):
    """⛔ This case ASSERTED the opposite until 2026-08-26.

    It said `ARCHIVE_NAME("darwin", "arm64")` must return a name ending in
    `.tar.gz` and containing `macos-arm64`. Since `firefox-21` there is no macOS
    asset at all, so the request must be REFUSED.

    It was deliberately not deleted: a decision nobody watches is a decision
    somebody undoes by accident. If a seal ever carried darwin again, this case
    would say so. The refusal comes from `Seal.asset_for`, which does not find
    the pair, and the source is that same `seal.json` - not a list written here.
    """
    with pytest.raises(NotImplementedError):
        ARCHIVE_NAME("darwin", machine)


@pytest.mark.unit
def test_archive_name_truly_unsupported_raises():
    with pytest.raises(NotImplementedError):
        ARCHIVE_NAME("plan9", "x86_64")


@pytest.mark.unit
def test_binary_basename_format():
    assert "firefox" in BINARY_BASENAME.lower()
    assert "stealth" in BINARY_BASENAME.lower()


# ---- Comprehensive ARCHIVE_NAME edge cases -------------------------------- #
# Same risk shape as bug #15: a missed format assumption (sha256sum binary
# mode) silently produced wrong output. Same class of bug here would be
# uppercase platform string or odd machine value passing through to a
# wrong-named asset on the CDN and 404-ing.

@pytest.mark.unit
@pytest.mark.parametrize("platform_key,machine,expected_substring", [
    ("win32",  "AMD64",     "win-x86_64.zip"),       # Windows reports AMD64
    ("win32",  "amd64",     "win-x86_64.zip"),       # lowercase variant
    ("win32",  "x86_64",    "win-x86_64.zip"),       # mingw-style
    ("linux",  "x86_64",    "linux-x86_64.tar.gz"),  # standard Linux
    ("linux",  "AMD64",     "linux-x86_64.tar.gz"),  # odd but plausible
    ("Linux",  "x86_64",    "linux-x86_64.tar.gz"),  # case-insensitive platform
    ("WIN32",  "AMD64",     "win-x86_64.zip"),       # ALL CAPS platform
])
def test_archive_name_accepts_case_variations(complete_archive_seal, platform_key, machine, expected_substring):
    """sys.platform / platform.machine() return inconsistent casing across
    OS versions and Python versions. The asset filename must be stable
    regardless - otherwise the CDN 404s."""
    assert ARCHIVE_NAME(platform_key, machine).endswith(expected_substring)


@pytest.mark.unit
@pytest.mark.parametrize("machine", ["i386", "i686", "ppc64le", "armv7l", "riscv64"])
def test_archive_name_rejects_unsupported_arches(machine):
    """Unsupported arches must raise NotImplementedError with the bad value
    in the message - silent fallback to a default arch would download the
    wrong binary, run, and fingerprint differently."""
    with pytest.raises(NotImplementedError, match=machine):
        ARCHIVE_NAME("linux", machine)


@pytest.mark.unit
@pytest.mark.parametrize("machine", ["arm64", "aarch64"])
def test_archive_name_arm64_follows_the_seal(machine):
    """ARCHIVE_NAME maps both arm64 spellings to the -arm64 asset when a seal
    carries one, and raises NotImplementedError without PyPI remedies when
    oss-invisible is not used."""
    seal = active_seal()
    if seal.is_local or any((a.platform, a.arch) == ("linux", "arm64") for a in seal.assets.values()):
        assert ARCHIVE_NAME("linux", machine) == f"{BINARY_BASENAME}-linux-arm64.tar.gz"
    elif seal.contract_n > 0 and "/oss-invisible/" in RELEASE_URL_TEMPLATE:
        with pytest.raises(NotImplementedError, match="firefox-55"):
            ARCHIVE_NAME("linux", machine)
    else:
        with pytest.raises(NotImplementedError, match="no asset for platform=linux arch=arm64") as info:
            ARCHIVE_NAME("linux", machine)
        assert "invisible-core<56" not in str(info.value)
    # The darwin line that stood here went with the mac on 2026-08-26; the
    # refusal has a case of its own, above.


@pytest.mark.unit
@pytest.mark.parametrize("platform_key", ["freebsd", "cygwin", "openbsd"])
def test_archive_name_rejects_unsupported_platforms(platform_key):
    """win32/linux/darwin are supported; other platforms must raise, not
    silently pick one of the three."""
    with pytest.raises(NotImplementedError, match=platform_key):
        ARCHIVE_NAME(platform_key, "x86_64")


# ---- ARCHIVE_NAME â†” DEFAULT_ENTRY_REL invariant ---------------------------- #
# For every supported platform there MUST be an entry in DEFAULT_ENTRY_REL,
# otherwise ensure_binary() will raise NotImplementedError AFTER having
# already downloaded a 110 MB tarball - terrible UX.

@pytest.mark.unit
def test_binary_entry_rel_covers_every_supported_platform(complete_archive_seal):
    """If ARCHIVE_NAME accepts a platform key, DEFAULT_ENTRY_REL must declare
    where the executable lives inside the archive for it.

    ⛔ The platform list used to be hand-written - `["win32", "linux",
    "darwin"]` - and went red by itself the day the mac left the seal. It is the
    same defect as `EXPECTED_ASSETS = 5` in `roll_seal.py`: a count, or a list,
    written somewhere that is not the authority goes stale at the first change
    of matrix. It is derived from `SUPPORTED_LEGS` now, which is the one
    declaration, and this case will hold for whatever set of legs we ship.
    """
    for plat, arch in SUPPORTED_LEGS:
        ARCHIVE_NAME(plat, arch)  # must not raise
        assert plat in DEFAULT_ENTRY_REL, (
            f"ARCHIVE_NAME accepts {plat!r} but DEFAULT_ENTRY_REL has no entry "
            f"- ensure_binary() will fail late after a 110 MB download."
        )


@pytest.mark.unit
def test_binary_entry_rel_extension_matches_platform():
    """firefox.exe on Windows, plain `firefox` on Linux."""
    assert DEFAULT_ENTRY_REL["win32"].endswith(".exe")
    assert not DEFAULT_ENTRY_REL["linux"].endswith(".exe")
    assert DEFAULT_ENTRY_REL["linux"] == "firefox"


# ---- RELEASE_URL_TEMPLATE shape ------------------------------------------- #

@pytest.mark.unit
def test_release_url_template_is_https():
    """No http://. GitHub redirects http but we never accept the redirect."""
    assert RELEASE_URL_TEMPLATE.startswith("https://github.com/")


@pytest.mark.unit
def test_release_url_template_has_required_placeholders():
    """{tag} and {asset} must both be present, otherwise _resolve_asset_urls
    won't format a usable URL and downloads fail with confusing 404s."""
    assert "{tag}" in RELEASE_URL_TEMPLATE
    assert "{asset}" in RELEASE_URL_TEMPLATE


@pytest.mark.unit
def test_release_url_template_formats_cleanly():
    """Confirm .format() actually substitutes - catches typos like {tags}."""
    url = RELEASE_URL_TEMPLATE.format(tag="firefox-99", asset="thing.zip")
    assert "{" not in url and "}" not in url
    assert "firefox-99" in url
    assert "thing.zip" in url


@pytest.mark.unit
def test_release_url_points_at_owned_repo():
    """The template MUST point at an owner/repo the maintainer actually
    controls. A typo here would direct everyone's downloads at a stranger's
    GitHub account - silent supply-chain risk."""
    assert "/idawnlight/firefox_antidetect_patch/" in RELEASE_URL_TEMPLATE, (
        f"RELEASE_URL_TEMPLATE was changed to point elsewhere: "
        f"{RELEASE_URL_TEMPLATE!r}. Update this test only if the move is intentional."
    )


# ---- Firefox upstream version sanity -------------------------------------- #

@pytest.mark.unit
def test_firefox_upstream_version_is_three_part_semver():
    parts = FIREFOX_UPSTREAM_VERSION.split(".")
    assert len(parts) >= 2, f"version too short: {FIREFOX_UPSTREAM_VERSION!r}"
    for p in parts:
        assert p.isdigit(), f"non-numeric segment in {FIREFOX_UPSTREAM_VERSION!r}"


@pytest.mark.unit
def test_binary_basename_includes_upstream_version():
    """The basename references the upstream version, so the asset filename
    on the CDN encodes which Firefox was patched. Bumping FIREFOX_UPSTREAM_VERSION
    without rebuilding would leave stale binaries - this guards against
    accidentally desyncing the two."""
    assert FIREFOX_UPSTREAM_VERSION in BINARY_BASENAME


@pytest.mark.unit
@pytest.mark.parametrize("plat", ["win32", "linux"])
def test_archive_name_includes_upstream_version(complete_archive_seal, plat):
    """Same desync guard, from the other direction."""
    assert FIREFOX_UPSTREAM_VERSION in ARCHIVE_NAME(plat, "x86_64")


@pytest.mark.unit
def test_default_archive_names_cover_exactly_the_legs_the_release_ships():
    seal = active_seal()
    for platform, arch in SUPPORTED_LEGS:
        try:
            asset = seal.asset_for(platform, arch)
        except NotImplementedError:
            with pytest.raises(NotImplementedError):
                ARCHIVE_NAME(platform, arch)
        else:
            assert ARCHIVE_NAME(platform, arch) == asset.name
