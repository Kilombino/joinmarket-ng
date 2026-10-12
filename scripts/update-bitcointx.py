#!/usr/bin/env python3
"""Update the maintained python-bitcointx release pin in source files."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from pathlib import Path
from typing import NamedTuple
from urllib.request import Request, urlopen

REPOSITORY = "m0wer/python-bitcointx"
RELEASE_API_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
USER_AGENT = "joinmarket-ng-dependency-updater/1.0"
VERSION_PATTERN = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
DIRECT_PIN_FILES = (
    Path("jmcore/pyproject.toml"),
    Path("jmwallet/pyproject.toml"),
    Path("jmwalletd/pyproject.toml"),
    Path("scripts/derive_bond_pubkey.py"),
    Path("scripts/sign_bond_cert_reference.py"),
    Path("scripts/sign_bond_mnemonic.py"),
)
SECURITY_TEST_PATH = Path("tests/test_security_workflows.py")
PIN_RE = re.compile(
    rf"https://github\.com/{REPOSITORY}/releases/download/"
    rf"python-bitcointx-v(?P<tag_version>{VERSION_PATTERN})/"
    rf"python_bitcointx-(?P<wheel_version>{VERSION_PATTERN})-py3-none-any\.whl"
    r"#sha256=(?P<digest>[a-f0-9]{64})"
)
TEST_VERSION_RE = re.compile(
    rf'(?m)^(BITCOINTX_VERSION = ")(?P<version>{VERSION_PATTERN})(")$'
)
TEST_DIGEST_RE = re.compile(
    r'(?m)^(BITCOINTX_WHEEL_SHA256 = (?:\(\n    )?")'
    r'(?P<digest>[a-f0-9]{64})("(?:\n\))?)$'
)


class UpdateError(RuntimeError):
    pass


class ReleasePin(NamedTuple):
    version: str
    wheel_url: str
    sha256: str

    @property
    def requirement_url(self) -> str:
        return f"{self.wheel_url}#sha256={self.sha256}"


class UpdateResult(NamedTuple):
    current_version: str
    changed_paths: tuple[Path, ...]


def fetch_latest_release() -> dict[str, object]:
    request = Request(
        RELEASE_API_URL,
        headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
    )
    with urlopen(request, timeout=120) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, dict):
        raise UpdateError("GitHub latest release response is not an object")
    return payload


def parse_release(payload: dict[str, object]) -> ReleasePin:
    if payload.get("draft") is not False or payload.get("prerelease") is not False:
        raise UpdateError(
            "Latest python-bitcointx release must be stable and published"
        )

    tag = payload.get("tag_name")
    if not isinstance(tag, str):
        raise UpdateError("Latest python-bitcointx release has no tag")
    tag_match = re.fullmatch(rf"python-bitcointx-v(?P<version>{VERSION_PATTERN})", tag)
    if tag_match is None:
        raise UpdateError(f"Unexpected python-bitcointx release tag: {tag}")
    version = tag_match.group("version")

    expected_name = f"python_bitcointx-{version}-py3-none-any.whl"
    expected_url = (
        f"https://github.com/{REPOSITORY}/releases/download/{tag}/{expected_name}"
    )
    assets = payload.get("assets")
    if not isinstance(assets, list):
        raise UpdateError("Latest python-bitcointx release has no assets array")
    matching_assets = [
        asset
        for asset in assets
        if isinstance(asset, dict) and asset.get("name") == expected_name
    ]
    if len(matching_assets) != 1:
        raise UpdateError(
            f"Expected one {expected_name} release asset, found {len(matching_assets)}"
        )

    asset = matching_assets[0]
    wheel_url = asset.get("browser_download_url")
    if wheel_url != expected_url:
        raise UpdateError(f"Unexpected python-bitcointx wheel URL: {wheel_url}")
    digest = asset.get("digest")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
    ):
        raise UpdateError("python-bitcointx wheel asset has no valid SHA-256 digest")
    return ReleasePin(version, expected_url, digest.removeprefix("sha256:"))


def _one_match(pattern: re.Pattern[str], text: str, path: Path) -> re.Match[str]:
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise UpdateError(
            f"Expected one python-bitcointx pin in {path}, found {len(matches)}"
        )
    return matches[0]


def _atomic_write(path: Path, text: str) -> None:
    mode = path.stat().st_mode
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as temporary:
            temporary.write(text)
            temporary_path = Path(temporary.name)
        temporary_path.chmod(mode)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def update_sources(repo_root: Path, latest: ReleasePin) -> UpdateResult:
    prepared: dict[Path, str] = {}
    current_pins: list[tuple[str, str]] = []

    for relative_path in DIRECT_PIN_FILES:
        path = repo_root / relative_path
        text = path.read_text(encoding="utf-8")
        match = _one_match(PIN_RE, text, relative_path)
        tag_version = match.group("tag_version")
        wheel_version = match.group("wheel_version")
        if tag_version != wheel_version:
            raise UpdateError(
                f"Inconsistent python-bitcointx versions in {relative_path}"
            )
        current_pins.append((tag_version, match.group("digest")))
        prepared[path] = PIN_RE.sub(latest.requirement_url, text, count=1)

    test_path = repo_root / SECURITY_TEST_PATH
    test_text = test_path.read_text(encoding="utf-8")
    version_match = _one_match(TEST_VERSION_RE, test_text, SECURITY_TEST_PATH)
    digest_match = _one_match(TEST_DIGEST_RE, test_text, SECURITY_TEST_PATH)
    current_pins.append((version_match.group("version"), digest_match.group("digest")))
    updated_test_text = TEST_VERSION_RE.sub(
        rf"\g<1>{latest.version}\g<3>", test_text, count=1
    )
    prepared[test_path] = TEST_DIGEST_RE.sub(
        rf"\g<1>{latest.sha256}\g<3>", updated_test_text, count=1
    )

    if len(set(current_pins)) != 1:
        raise UpdateError("Existing python-bitcointx source pins are inconsistent")
    current_version = current_pins[0][0]

    changed_paths = tuple(
        path
        for path, updated_text in prepared.items()
        if path.read_text(encoding="utf-8") != updated_text
    )
    for path in changed_paths:
        _atomic_write(path, prepared[path])
    return UpdateResult(current_version, changed_paths)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    try:
        latest = parse_release(fetch_latest_release())
        result = update_sources(args.repo_root.resolve(), latest)
    except (OSError, UpdateError, json.JSONDecodeError) as error:
        print(f"Error: {error}")
        return 1

    if result.changed_paths:
        print(
            f"Updated python-bitcointx {result.current_version} -> {latest.version} "
            f"in {len(result.changed_paths)} source files"
        )
    else:
        print(f"python-bitcointx is up to date ({latest.version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
