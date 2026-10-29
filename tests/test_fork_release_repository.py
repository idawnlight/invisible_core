import pytest

from invisible_core.constants import release_url_template
from invisible_core.download import _parse_owner_repo


@pytest.mark.unit
def test_fork_repository_is_the_default_and_can_be_overridden(monkeypatch):
    import os
    import subprocess
    import sys

    environment = os.environ.copy()
    environment.pop("INVISIBLE_FIREFOX_RELEASE_REPOSITORY", None)
    code = "from invisible_core.constants import RELEASE_URL_TEMPLATE; print(RELEASE_URL_TEMPLATE)"
    default = subprocess.check_output([sys.executable, "-c", code], env=environment, text=True).strip()
    assert default == "https://github.com/idawnlight/firefox_antidetect_patch/releases/download/{tag}/{asset}"
    environment["INVISIBLE_FIREFOX_RELEASE_REPOSITORY"] = "example/firefox-fork"
    override = subprocess.check_output([sys.executable, "-c", code], env=environment, text=True).strip()
    assert override == "https://github.com/example/firefox-fork/releases/download/{tag}/{asset}"


@pytest.mark.unit
def test_fork_release_url_is_used_by_the_download_and_api_routes():
    template = release_url_template("example/firefox-fork")
    assert template.format(tag="firefox-159", asset="engine.tar.gz") == (
        "https://github.com/example/firefox-fork/releases/download/firefox-159/engine.tar.gz"
    )
    assert _parse_owner_repo(template) == ("example", "firefox-fork")


@pytest.mark.unit
@pytest.mark.parametrize("repository", ["", "owner", "owner/repo/extra", "https://github.com/a/b", "a/b?x=1"])
def test_invalid_repository_is_rejected(repository):
    with pytest.raises(ValueError):
        release_url_template(repository)
