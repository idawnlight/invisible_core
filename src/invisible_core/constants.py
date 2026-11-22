"""Constants. Everything that describes the engine is a projection of the seal.

No engine fact is hand-edited here. BINARY_VERSION and FIREFOX_UPSTREAM_VERSION
used to be two literals that had to move together, which is how a tag and a base
version could disagree inside one published commit. They, BUILD_ID, CONTRACT_N,
SEAL_DIGEST, SOURCE_COMMIT and everything computed from them (BINARY_BASENAME,
UA_VERSION, USER_AGENT, and ARCHIVE_NAME, which returns the sealed asset name
verbatim whenever the seal has assets) come out of seal.json, which CI generated
from the archives it published, so they cannot disagree with each other or with
the engine.

What IS hand-written, because no seal carries it: the "firefox-" / "-stealth"
affixes and the per-platform archive suffixes that surround the sealed version
in BINARY_BASENAME / ARCHIVE_NAME, RELEASE_URL_TEMPLATE (the repo that hosts the
releases), and the four GEOIP_* constants (a third-party repo, its asset
name and its download URL). Those move only when the hosting repo, the archive
layout or the upstream GeoIP project moves.

The NAMES are the binary/wrapper contract and never change.
"""
from __future__ import annotations

import os
import re
from typing import NamedTuple

from . import environment
from ._version import CORE_REVISION, __version__ as PKG_VERSION
from .seal import active_seal, normalize_arch

_SEAL = active_seal()

BINARY_VERSION: str = _SEAL.tag
FIREFOX_UPSTREAM_VERSION: str = _SEAL.upstream_version
# The BuildID of the leg THIS host runs. The published legs (SUPPORTED_LEGS in
# seal.py) are separate CI builds with separate BuildIDs, so there is no
# seal-wide value to export here; the launch-time check compares against the
# per-asset one, not against this.
BUILD_ID: str = _SEAL.build_id
CONTRACT_N: int = _SEAL.contract_n
SEAL_DIGEST: str = _SEAL.digest
SOURCE_COMMIT: str = _SEAL.source_commit

BINARY_BASENAME: str = f"firefox-{FIREFOX_UPSTREAM_VERSION}-stealth"

# Spoofed User-Agent. Firefox puts only MAJOR.MINOR in the UA (a real 150.0.1
# build reports "Firefox/150.0"), so the truncation is part of the form.
UA_VERSION: str = ".".join(FIREFOX_UPSTREAM_VERSION.split(".")[:2])
USER_AGENT: str = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{UA_VERSION}) "
    f"Gecko/20100101 Firefox/{UA_VERSION}"
)

# The other two halves of the same claim. They live here, beside the
# User-Agent they have to agree with, because they used to be written out
# twice: once in prefs._NAVIGATOR_OVERRIDES and once in the sampler's
# _LOCKED, with nothing tying the two together. USER_AGENT was already
# centralised; these were not, so they were the pair that could drift.
#
# The drift is not hypothetical. The same shape was found and fixed on
# 2026-08-09 for max_touch_points, where a stale second copy silently won
# over the constant that was supposed to own the value, and it was invisible
# because both copies said 0.
PLATFORM_OVERRIDE: str = "Win32"
OSCPU_OVERRIDE: str = "Windows NT 10.0; Win64; x64"

# Height of the Windows taskbar in CSS pixels at 100% DPI, i.e. how much
# shorter screen.availHeight is than screen.height. It lives here, in the
# module both the sampler and the profile already import, because it was the
# same number written out in three places - the generator, nsScreen.cpp and
# nsGlobalWindowOuter.cpp - with nothing tying them together.
TASKBAR_PX: int = 48

class WindowFrame(NamedTuple):
    """The window frame of Windows Firefox at one display scale, in DEVICE
    pixels."""
    #: Windows' invisible resize border, on the left, right and bottom of every
    #: window and on top of a popup. A maximized window sits this far OFF the
    #: screen on three sides.
    border: int
    #: A maximized window: from the screen top to the content top (tab strip
    #: plus toolbar, seen from the screen).
    maximized_ui: int
    #: A popup: from the window top, border included, to the content top.
    popup_ui: int
    #: Where a popup opened without left/top is put, on both axes.
    popup_position: int


#: The window frame per display scale, measured on retail Firefox 151 on
#: Windows 11 on 2026-10-08, lending the display scale (the workbench's
#: scripts/window_geometry/scales.py). Measured, not chosen: a page reads
#: screenX, outerWidth - availWidth and mozInnerScreenY in one line each, and
#: retail answers -8, 16 and 85 at 100%, -7, 15 and 85.6 at 125%. In device
#: pixels the four rows are one rule; every CSS value is the device value
#: divided by the scale with Gecko's rounding, done by the engine.
#:
#: The keys are the DOMAIN: the four scales the screen table gives personas
#: (cpt_screen_given_class_tier.json). A scale outside it has no measured frame
#: and is refused, never interpolated (engine rule 2).
#:
#: ⛔ It replaces CHROME_W = 0 and CHROME_H = 85 with window_x = window_y = 0,
#: from a 2026-08-09 measurement of a window that was not a maximized Windows
#: Firefox (a 768-pixel-tall screen, no resize border): it described a window
#: at the screen origin with no side border, which Windows never draws
#: maximized, and every popup answered the same numbers.
WINDOW_FRAME_BY_DPR: dict = {
    1.0: WindowFrame(border=8, maximized_ui=85, popup_ui=72, popup_position=4),
    1.25: WindowFrame(border=9, maximized_ui=107, popup_ui=90, popup_position=4),
    1.5: WindowFrame(border=11, maximized_ui=127, popup_ui=106, popup_position=4),
    2.0: WindowFrame(border=13, maximized_ui=169, popup_ui=139, popup_position=4),
}



def ARCHIVE_NAME(platform_key: str, machine: str) -> str:
    """The platform-specific archive filename, taken from the seal when it has
    assets (the sealed name is the published name, by construction) and
    reconstructed only for a local seal."""
    pk = platform_key.lower()
    arch = normalize_arch(machine)
    if not _SEAL.is_local:
        return _SEAL.asset_for(pk, machine).name
    if pk == "win32":
        return f"{BINARY_BASENAME}-win-{arch}.zip"
    if pk == "linux":
        return f"{BINARY_BASENAME}-linux-{arch}.tar.gz"
    raise NotImplementedError(f"unsupported platform: {platform_key}")

# GitHub release URL template. Binaries are hosted on the source repo
# (firefox_antidetect_patch) since firefox-14 - the same repo that builds them,
# so every consumer fetches from one place: the Playwright wrapper, and until
# its 2026-08-18 deletion, the direct-launch profile-manager too. (firefox-13
# and earlier lived on invisible_playwright.)
def release_url_template(repository: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+", repository):
        raise ValueError(f"expected a GitHub owner/repository, got {repository!r}")
    return f"https://github.com/{repository}/releases/download/{{tag}}/{{asset}}"


RELEASE_URL_TEMPLATE = release_url_template(os.environ.get(
    environment.ENGINE_REPOSITORY, "idawnlight/firefox_antidetect_patch"))

# ─────────────────────────────────────────────────────────────────────────
#  GeoIP database (timezone="auto" → resolve IANA zone from proxy egress IP)
# ─────────────────────────────────────────────────────────────────────────
# daijro/geoip-all-in-one merges IP2Location LITE + GeoLite2 + DB-IP
# into a single mmdb (country ISO + coordinates + IANA timezone via tzfpy),
# rebuilt weekly. GPL-3.0, so we DOWNLOAD it at runtime into the user cache
# (like the Firefox binary) rather than bundling it into this MIT package. The
# `-all` variant covers IPv4+IPv6. _geoip_db.py NEVER pins a tag (old releases
# are pruned, so a pinned tag eventually 404s): on every check interval it
# resolves the CURRENT latest tag from the `releases/latest/download` permalink
# (no GitHub API, no rate limit) and pulls it if newer than the cache.
GEOIP_REPO: str = "daijro/geoip-all-in-one"
GEOIP_ASSET: str = "geoip-aio-all.mmdb.zip"
GEOIP_MMDB_NAME: str = "geoip-aio-all.mmdb"
GEOIP_RELEASE_URL_TEMPLATE: str = (
    "https://github.com/daijro/geoip-all-in-one/releases/download/{tag}/{asset}"
)

# ─────────────────────────────────────────────────────────────────────────
#  Preloaded intermediate certificates (Mozilla's Remote Settings, collection security-state/intermediates)
# ─────────────────────────────────────────────────────────────────────────
# A retail Firefox keeps the intermediates of the public web preloaded in cert_storage, from this collection; the engine no longer syncs it, so the core
# downloads it from the same service Firefox uses (from the USER's Python, never from the engine), verifies it, and hands it to the engine's generate mode
# as a file (the pref INTERMEDIATES_PREF, written only on the work profile of a generation). The addresses are the ones the engine's own source reads: the
# server is the default of `services.settings.server` (`toolkit/modules/AppConstants.sys.mjs`, REMOTE_SETTINGS_SERVER_URLS), the changes feed is
# `Utils.CHANGES_PATH` (`services/settings/Utils.sys.mjs`), the changeset path is `RemoteSettingsClient._fetchChangeset`, and the bundle is
# `Downloader.cacheAll` (`services/settings/Attachments.sys.mjs`).
REMOTE_SETTINGS_SERVER: str = "https://firefox.settings.services.mozilla.com/v2"
INTERMEDIATES_COLLECTION_ID: str = "intermediates"
#: The server's root answers `capabilities.attachments.base_url`, where every attachment (and the bundle) lives.
INTERMEDIATES_SERVER_INFO_URL: str = REMOTE_SETTINGS_SERVER + "/"
#: Under that base: ONE zip with every attachment of the collection (`<record id>.meta.json` + `<record id>`).
INTERMEDIATES_BUNDLE_PATH: str = "bundles/security-state--intermediates.zip"
#: The file the engine reads, and the pref that names it (an absolute path).
INTERMEDIATES_FILE_NAME: str = "intermediates.json"
INTERMEDIATES_PREF: str = "zoom.stealth.intermediates.file"

# ─────────────────────────────────────────────────────────────────────────
#  The security state of a retail profile, as ready files (intermediates, OneCRL, CRLite)
# ─────────────────────────────────────────────────────────────────────────
# A retail Firefox 159 keeps three collections of the bucket `security-state` in cert_storage (`security/manager/ssl/RemoteSecuritySettings.sys.mjs`):
# `intermediates` (above), `onecrl` (revocations of intermediates and roots, records without attachments, every record passed to `setRevocations` with
# STATE_ENFORCE) and `cert-revocations` (the CRLite filters: of the records whose `filter_expression` holds for the channel `security.pki.crlite_channel`,
# exactly one full filter, `incremental: false`, and the deltas, each attachment checked for sha256 and size). The core downloads them from the same service,
# hands them ONCE to the engine in its generate mode (the four prefs below, on an empty work profile), and keeps what the engine wrote
# (`<profile>/security_state/` and `securitystate-result.json`); a launch copies that directory into its profile and sets no pref of the security state.
SECURITY_STATE_BUCKET: str = "security-state"
#: The timestamps of every collection of the bucket, in one answer of the changes feed (a few hundred bytes).
SECURITY_STATE_LATEST_URL: str = (
    REMOTE_SETTINGS_SERVER + "/buckets/monitor/collections/changes/changeset?_expected=0&bucket=security-state"
)
#: One collection of the bucket (`expected` = its timestamp from the feed, or 0).
SECURITY_STATE_CHANGESET_URL_TEMPLATE: str = (
    REMOTE_SETTINGS_SERVER + "/buckets/security-state/collections/{collection}/changeset?_expected={expected}"
)
ONECRL_COLLECTION_ID: str = "onecrl"
CRLITE_COLLECTION_ID: str = "cert-revocations"
#: The default of `security.pki.crlite_channel` on desktop (`modules/libpref/init/StaticPrefList.yaml`); the core sets no other.
CRLITE_CHANNEL: str = "default"
#: cert_storage treats the filters as absent ten days after the last `setFullCRLiteFilter`/`addCRLiteDelta` (`cert_storage/src/lib.rs`, `is_crlite_fresh` on `last_crlite_update`).
CRLITE_MAX_AGE_S: int = 10 * 24 * 3600
#: The files the engine reads in its generate mode (formats in `_revocations.py` and `_intermediates.py`).
ONECRL_FILE_NAME: str = "onecrl.json"
CRLITE_FILE_NAME: str = "crlite.json"
#: The generate mode: the switch and the three inputs (absolute paths). Written only on the work profile of a generation, never on a launch.
SECURITY_STATE_GENERATE_PREF: str = "zoom.stealth.securitystate.generate"
ONECRL_PREF: str = "zoom.stealth.onecrl.file"
CRLITE_PREF: str = "zoom.stealth.crlite.file"
#: What the generate mode leaves in the work profile: cert_storage's directory (copied as is into every profile) and the engine's report.
SECURITY_STATE_DIR_NAME: str = "security_state"
SECURITY_STATE_RESULT_NAME: str = "securitystate-result.json"
