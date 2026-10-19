from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _load_update_flatpak_deps_module():
    script_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "update-flatpak-deps.py"
    )
    spec = importlib.util.spec_from_file_location("update_flatpak_deps", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_replace_url_sha_updates_tor_entry() -> None:
    module = _load_update_flatpak_deps_module()
    manifest_path = (
        Path(__file__).resolve().parents[1] / "flatpak" / "org.joinmarketng.JamNG.yml"
    )
    manifest_text = manifest_path.read_text(encoding="utf-8")

    current_url, current_sha = module.extract_url_sha(
        module.TOR_RE, manifest_text, "tor"
    )
    assert current_url.startswith("https://dist.torproject.org/tor-")
    assert len(current_sha) == 64

    new_url = "https://dist.torproject.org/tor-0.4.9.99.tar.gz"
    new_sha = "a" * 64
    updated_text = module.replace_url_sha(
        module.TOR_RE, manifest_text, new_url, new_sha, "tor"
    )

    assert new_url in updated_text
    assert f"sha256: {new_sha}" in updated_text


def test_replace_jam_commit_updates_commit() -> None:
    module = _load_update_flatpak_deps_module()
    manifest_path = (
        Path(__file__).resolve().parents[1] / "flatpak" / "org.joinmarketng.JamNG.yml"
    )
    manifest_text = manifest_path.read_text(encoding="utf-8")

    current_commit = module.extract_jam_commit(manifest_text)
    assert len(current_commit) == 40

    new_commit = "f" * 40
    updated_text = module.replace_jam_commit(manifest_text, new_commit)

    assert f"commit: {new_commit}" in updated_text
    assert f"commit: {current_commit}" not in updated_text


def test_replace_jam_compose_pins_updates_both_dependencies() -> None:
    module = _load_update_flatpak_deps_module()
    compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    compose_text = compose_path.read_text(encoding="utf-8")

    current_ref, current_docker_commit = module.extract_jam_compose_pins(compose_text)
    assert current_ref.startswith("v")
    assert len(current_docker_commit) == 40

    new_ref = "v9.8.7-beta.6"
    new_docker_commit = "d" * 40
    updated_text = module.replace_jam_compose_pins(
        compose_text,
        new_ref,
        new_docker_commit,
    )

    assert module.extract_jam_compose_pins(updated_text) == (
        new_ref,
        new_docker_commit,
    )
    assert current_ref not in updated_text
    assert current_docker_commit not in updated_text


def test_replace_jam_test_commit_updates_expectation() -> None:
    module = _load_update_flatpak_deps_module()
    test_path = (
        Path(__file__).resolve().parents[1] / "tests" / "test_jmwalletd_dockerfile.py"
    )
    test_text = test_path.read_text(encoding="utf-8")

    current_commit = module.extract_jam_test_commit(test_text)
    new_commit = "d" * 40
    updated_text = module.replace_jam_test_commit(test_text, new_commit)

    assert module.extract_jam_test_commit(updated_text) == new_commit
    assert current_commit not in updated_text


def test_replace_jam_test_ref_updates_expectation() -> None:
    module = _load_update_flatpak_deps_module()
    test_path = (
        Path(__file__).resolve().parents[1] / "tests" / "test_jmwalletd_dockerfile.py"
    )
    test_text = test_path.read_text(encoding="utf-8")

    current_ref = module.extract_jam_test_ref(test_text)
    new_ref = "v9.8.7-beta.6"
    updated_text = module.replace_jam_test_ref(test_text, new_ref)

    assert module.extract_jam_test_ref(updated_text) == new_ref
    assert current_ref not in updated_text


def test_extract_jam_test_commit_rejects_duplicate_pin() -> None:
    module = _load_update_flatpak_deps_module()
    test_text = f'''JAM_DOCKER_COMMIT = "{"a" * 40}"
JAM_DOCKER_COMMIT = "{"b" * 40}"
'''

    try:
        module.extract_jam_test_commit(test_text)
    except module.UpdateError as error:
        assert "found 2" in str(error)
    else:
        raise AssertionError("Expected duplicate JAM test pins to be rejected")


def test_extract_jam_test_ref_rejects_duplicate_pin() -> None:
    module = _load_update_flatpak_deps_module()
    test_text = """JAM_REPO_REF = "v2.0.0-beta.2"
JAM_REPO_REF = "v2.0.0-beta.3"
"""

    try:
        module.extract_jam_test_ref(test_text)
    except module.UpdateError as error:
        assert "found 2" in str(error)
    else:
        raise AssertionError("Expected duplicate JAM test refs to be rejected")


def test_report_jam_docker_pins_detects_stale_test_expectation() -> None:
    module = _load_update_flatpak_deps_module()
    latest_commit = "a" * 40

    assert module.report_jam_docker_pins(
        latest_commit,
        "b" * 40,
        latest_commit,
    )


def test_report_jam_release_pins_detects_stale_test_expectation() -> None:
    module = _load_update_flatpak_deps_module()
    latest_ref = "v2.0.0-beta.3"

    assert module.report_jam_release_pins(
        latest_ref,
        "v2.0.0-beta.2",
        latest_ref,
    )


def test_replace_jam_compose_pins_only_updates_playwright_base_service() -> None:
    module = _load_update_flatpak_deps_module()
    old_commit = "a" * 40
    other_commit = "b" * 40
    compose_text = f"""services:
  other:
    build:
      context: ${{JAM_DOCKER_CONTEXT:-https://github.com/joinmarket-webui/jam-docker.git#{other_commit}:standalone-ng}}
      args:
        JAM_REPO_REF: ${{JAM_REPO_REF:-v1.0.0}}
  jam-playwright-base:
    build:
      context: ${{JAM_DOCKER_CONTEXT:-https://github.com/joinmarket-webui/jam-docker.git#{old_commit}:standalone-ng}}
      args:
        JAM_REPO_REF: ${{JAM_REPO_REF:-v2.0.0-beta.2}}
  following-service:
    image: example
"""

    updated_text = module.replace_jam_compose_pins(
        compose_text,
        "v2.0.0",
        "c" * 40,
    )

    assert "${JAM_REPO_REF:-v1.0.0}" in updated_text
    assert other_commit in updated_text
    assert module.extract_jam_compose_pins(updated_text) == ("v2.0.0", "c" * 40)


def test_extract_jam_compose_pins_rejects_duplicate_pin() -> None:
    module = _load_update_flatpak_deps_module()
    commit = "a" * 40
    compose_text = f"""services:
  jam-playwright-base:
    build:
      context: ${{JAM_DOCKER_CONTEXT:-https://github.com/joinmarket-webui/jam-docker.git#{commit}:standalone-ng}}
      args:
        JAM_REPO_REF: ${{JAM_REPO_REF:-v2.0.0-beta.2}}
        JAM_REPO_REF: ${{JAM_REPO_REF:-v2.0.0-beta.1}}
"""

    try:
        module.extract_jam_compose_pins(compose_text)
    except module.UpdateError as error:
        assert "found 2" in str(error)
    else:
        raise AssertionError("Expected duplicate JAM refs to be rejected")


def test_latest_jam_release_includes_prereleases(monkeypatch) -> None:
    module = _load_update_flatpak_deps_module()
    stable_commit = "a" * 40
    beta_tag_object = "b" * 40
    beta_commit = "c" * 40
    output = (
        f"{stable_commit}\trefs/tags/v0.4.1\n"
        f"{beta_tag_object}\trefs/tags/v2.0.0-beta.2\n"
        f"{beta_commit}\trefs/tags/v2.0.0-beta.2^{{}}\n"
        f"{'d' * 40}\trefs/tags/not-a-version\n"
    )
    monkeypatch.setattr(
        module.subprocess, "check_output", lambda *_args, **_kwargs: output
    )

    assert module.latest_jam_release() == (
        "v2.0.0-beta.2",
        beta_commit,
    )


def test_parse_remote_tags_prefers_peeled_commit() -> None:
    module = _load_update_flatpak_deps_module()
    tag_object = "a" * 40
    commit = "b" * 40
    output = (
        f"{tag_object}\trefs/tags/v2.0.0-beta.2\n"
        f"{commit}\trefs/tags/v2.0.0-beta.2^{{}}\n"
    )
    assert module.parse_remote_tags(output)["v2.0.0-beta.2"] == commit


def test_parse_remote_tags_keeps_lightweight_commit() -> None:
    module = _load_update_flatpak_deps_module()
    commit = "a" * 40

    assert module.parse_remote_tags(f"{commit}\trefs/tags/v2.0.0-beta.2\n") == {
        "v2.0.0-beta.2": commit
    }


def test_jam_release_sort_key_orders_numeric_prereleases() -> None:
    module = _load_update_flatpak_deps_module()
    tags = ["v2.0.0-beta.2", "v2.0.0-beta.10", "v2.0.0-beta.9"]

    assert max(tags, key=module.jam_release_sort_key) == "v2.0.0-beta.10"


def test_jam_release_sort_key_follows_semver_precedence() -> None:
    module = _load_update_flatpak_deps_module()
    tags = [
        "v2.0.0-beta",
        "v2.0.0-beta.2",
        "v2.0.0-rc.1",
        "v2.0.0",
        "v2.0.1-beta.1",
    ]

    assert sorted(tags, key=module.jam_release_sort_key) == tags
    assert module.jam_release_sort_key("v2.0.0+build.2") == (
        module.jam_release_sort_key("v2.0.0+build.1")
    )


def test_jam_release_pattern_rejects_invalid_semver() -> None:
    module = _load_update_flatpak_deps_module()

    for tag in (
        "v02.0.0",
        "v2.0.0-beta.02",
        "v2.0.0-beta..2",
        "v2.0.0-beta.",
        "v2.0.0+build..2",
    ):
        assert module.JAM_RELEASE_TAG_RE.fullmatch(tag) is None


def test_latest_remote_commit_rejects_multiple_refs(monkeypatch) -> None:
    module = _load_update_flatpak_deps_module()
    output = f"{'a' * 40}\trefs/heads/main\n{'b' * 40}\trefs/heads/other\n"
    monkeypatch.setattr(
        module.subprocess, "check_output", lambda *_args, **_kwargs: output
    )

    try:
        module.latest_remote_commit(
            "https://example.com/repo.git", "refs/heads/main", "test"
        )
    except module.UpdateError as error:
        assert "Expected one test ref" in str(error)
    else:
        raise AssertionError("Expected multiple remote refs to be rejected")


def test_latest_tor_version_selects_highest(monkeypatch) -> None:
    module = _load_update_flatpak_deps_module()
    html = """
    <a href='tor-0.4.8.23.tar.gz'>tor-0.4.8.23.tar.gz</a>
    <a href='tor-0.4.9.5.tar.gz'>tor-0.4.9.5.tar.gz</a>
    <a href='tor-0.4.9.6.tar.gz'>tor-0.4.9.6.tar.gz</a>
    """
    monkeypatch.setattr(module, "fetch_text", lambda _url: html)

    assert module.latest_tor_version() == "0.4.9.6"


def test_latest_tor_version_does_not_freeze_the_release_series(monkeypatch) -> None:
    module = _load_update_flatpak_deps_module()
    monkeypatch.setattr(
        module,
        "fetch_text",
        lambda _url: "tor-0.4.9.6.tar.gz tor-1.0.0.tar.gz tor-1.1.0-alpha.tar.gz",
    )
    assert module.latest_tor_version() == "1.0.0"


def test_native_pin_update_is_coordinated_and_preserves_unrelated_sources() -> None:
    module = _load_update_flatpak_deps_module()
    old, new, other = "a" * 40, "b" * 40, "c" * 40
    manifest = (
        f"- name: libsecp256k1\n  commit: {old}\n- name: other\n  commit: {other}\n"
    )
    files = {
        Path("ci.yaml"): f"git fetch origin {old}",
        Path("install.md"): f"pin: {old}",
    }
    updated, companions = module.replace_secp256k1_pins(manifest, files, new)
    assert f"commit: {new}" in updated
    assert f"commit: {other}" in updated
    assert companions == {path: text.replace(old, new) for path, text in files.items()}
    assert module.replace_secp256k1_pins(updated, companions, new) == (
        updated,
        companions,
    )


def test_native_pin_update_rejects_drift_before_changing_files() -> None:
    module = _load_update_flatpak_deps_module()
    manifest = f"- name: libsecp256k1\n  commit: {'a' * 40}\n"
    files = {Path("ci.yaml"): f"git fetch origin {'b' * 40}"}
    with pytest.raises(module.UpdateError, match="matching libsecp256k1 pin"):
        module.replace_secp256k1_pins(manifest, files, "c" * 40)


def test_native_release_resolution_uses_the_peeled_tag(monkeypatch) -> None:
    module = _load_update_flatpak_deps_module()
    tag, commit = "v9.8.7", "b" * 40
    monkeypatch.setattr(module, "latest_release", lambda _repo: {"tag_name": tag})
    monkeypatch.setattr(
        module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: (
            f"{'a' * 40}\trefs/tags/{tag}\n{commit}\trefs/tags/{tag}^{{}}\n"
        ),
    )
    assert module.latest_secp256k1_commit() == commit


def test_latest_libsodium_source_url_prefers_release_asset() -> None:
    module = _load_update_flatpak_deps_module()
    release = {
        "tag_name": "1.0.21-RELEASE",
        "assets": [
            {
                "name": "libsodium-1.0.21.tar.gz",
                "browser_download_url": "https://example.com/libsodium-1.0.21.tar.gz",
            }
        ],
        "tarball_url": "https://api.github.com/repos/jedisct1/libsodium/tarball/1.0.21-RELEASE",
    }

    assert (
        module.latest_libsodium_source_url(release)
        == "https://example.com/libsodium-1.0.21.tar.gz"
    )


def test_latest_libsodium_source_url_falls_back_to_download_site() -> None:
    module = _load_update_flatpak_deps_module()
    release = {
        "tag_name": "1.0.22-RELEASE",
        "assets": [],
        "tarball_url": "https://api.github.com/repos/jedisct1/libsodium/tarball/1.0.22-RELEASE",
    }

    assert (
        module.latest_libsodium_source_url(release)
        == "https://download.libsodium.org/libsodium/releases/libsodium-1.0.22.tar.gz"
    )


def test_latest_libsodium_source_url_falls_back_to_tarball_url() -> None:
    module = _load_update_flatpak_deps_module()
    release = {
        "tag_name": "latest",
        "assets": [],
        "tarball_url": "https://api.github.com/repos/jedisct1/libsodium/tarball/1.0.22-RELEASE",
    }

    assert (
        module.latest_libsodium_source_url(release)
        == "https://api.github.com/repos/jedisct1/libsodium/tarball/1.0.22-RELEASE"
    )
