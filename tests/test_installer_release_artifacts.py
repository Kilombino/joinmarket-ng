from __future__ import annotations

import os
import hashlib
import shutil
import stat
import subprocess
import textwrap
from collections.abc import Generator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGN_RELEASE_SCRIPT = REPO_ROOT / "scripts" / "sign-release.sh"
TEST_FINGERPRINT = "111122223333444455556666777788889999AAAA"


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def run_git(repo_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        text=True,
        capture_output=True,
        check=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Test User",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test User",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        },
    )


@pytest.fixture
def gpg_home(tmp_path: Path) -> Generator[Path, None, None]:
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    try:
        yield home
    finally:
        gpgconf = shutil.which("gpgconf")
        if gpgconf is not None:
            subprocess.run(
                [gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
                capture_output=True,
                timeout=30,
                check=False,
            )


@pytest.mark.skipif(shutil.which("gpg") is None, reason="GnuPG is required")
def test_deduplicated_manifest_signatures_work_with_existing_consumers(
    tmp_path: Path, gpg_home: Path
) -> None:
    repo_dir = tmp_path / "repo"
    scripts_dir = repo_dir / "scripts"
    pubkeys_dir = repo_dir / "signatures" / "pubkeys"
    bin_dir = tmp_path / "bin"
    scripts_dir.mkdir(parents=True)
    pubkeys_dir.mkdir(parents=True)
    bin_dir.mkdir()
    for name in ("sign-release.sh", "verify-release.sh"):
        shutil.copy2(REPO_ROOT / "scripts" / name, scripts_dir / name)
    shutil.copy2(REPO_ROOT / "install.sh", repo_dir / "install.sh")
    run_git(repo_dir, "init", "--initial-branch=main")
    run_git(repo_dir, "config", "commit.gpgsign", "false")
    run_git(repo_dir, "add", ".")
    run_git(repo_dir, "commit", "-m", "test: release source")
    commit = run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    run_git(repo_dir, "tag", "1.2.3")
    env = {
        **os.environ,
        "GNUPGHOME": str(gpg_home),
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
    }

    def run(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            cwd=repo_dir,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )

    fingerprints = []
    for name in ("first", "second"):
        run(
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            f"{name} <{name}@example.invalid>",
            "ed25519",
            "sign",
            "0",
        )
        fingerprint = next(
            line.split(":")[9]
            for line in run(
                "gpg", "--with-colons", "--list-keys", name
            ).stdout.splitlines()
            if line.startswith("fpr:")
        )
        fingerprints.append(fingerprint)
        run(
            "gpg",
            "--armor",
            "--output",
            str(pubkeys_dir / f"{fingerprint}.asc"),
            "--export",
            fingerprint,
        )
    (repo_dir / "signatures" / "trusted-keys.txt").write_text(
        "".join(f"{fingerprint} Test Signer\n" for fingerprint in fingerprints)
    )
    manifest = tmp_path / "release-manifest-1.2.3.txt"
    manifest.write_text(
        f"# Version: 1.2.3\ncommit: {commit}\nsource_date_epoch: 1234567890\n"
        f"example-manifest: sha256:{hashlib.sha256(b'raw-manifest').hexdigest()}\n"
    )
    curl_log = tmp_path / "curl-log"
    write_executable(
        bin_dir / "curl",
        textwrap.dedent(
            f"""#!/usr/bin/env bash
            set -euo pipefail
            url=""
            output=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -o) output="$2"; shift 2 ;;
                    https://*) url="$1"; shift ;;
                    *) shift ;;
                esac
            done
            echo "$url" >> "{curl_log}"
            case "$url" in
                */release-manifest-1.2.3.txt) input="{manifest}" ;;
                */releases/download/1.2.3/install.sh) input="{repo_dir}/install.sh" ;;
                */signatures/pubkeys/*.asc) input="{pubkeys_dir}/${{url##*/}}" ;;
                */signatures/1.2.3/*.sig) input="{repo_dir}/signatures/1.2.3/${{url##*/}}" ;;
                *) exit 22 ;;
            esac
            cp "$input" "$output"
            """
        ),
    )
    write_executable(bin_dir / "jq", "#!/usr/bin/env bash\nexit 0\n")
    write_executable(
        bin_dir / "docker", "#!/usr/bin/env bash\nprintf '%s' raw-manifest\n"
    )
    for fingerprint in fingerprints:
        run(
            "bash",
            str(scripts_dir / "sign-release.sh"),
            "1.2.3",
            "--manifest",
            str(manifest),
            "--key",
            fingerprint,
            "--no-reproduce",
            "--no-push",
        )
    copies = list((repo_dir / "signatures" / "1.2.3").glob("*-manifest.txt"))
    assert [path.name for path in copies] == [f"{fingerprints[0]}-manifest.txt"]
    # Both consumers must work without falling back to even the retained copy.
    copies[0].unlink()
    result = run(
        "bash", str(scripts_dir / "verify-release.sh"), "1.2.3", "--require-installer"
    )
    assert "Valid signatures: 2" in result.stdout
    assert "Valid installer signatures: 2" in result.stdout
    result = run(
        "bash",
        "-c",
        f'''source "{repo_dir}/install.sh"
TRUSTED_GPG_FINGERPRINTS=({" ".join(fingerprints)})
SKIP_VERIFY=false
REQUIRED_GPG_SIGNATURES=2
verify_release_signature "1.2.3" "{commit}"
''',
    )
    assert "verified (2 trusted signature(s))" in result.stdout
    assert not any(
        url.endswith("-manifest.txt") for url in curl_log.read_text().splitlines()
    )


@pytest.mark.parametrize(
    ("stored_copy", "published_copy", "download_status", "auto_commit", "omit_copy"),
    [
        pytest.param(None, None, 22, False, False, id="first-signer"),
        pytest.param(
            "identical", "identical", 0, False, True, id="published-duplicate"
        ),
        pytest.param("identical", None, 22, False, False, id="unavailable-ci"),
        pytest.param(
            "identical", "different", 0, False, False, id="different-ci-bytes"
        ),
        pytest.param(
            "identical", "identical", 22, False, False, id="failed-partial-download"
        ),
        pytest.param(
            "different", "identical", 0, False, False, id="different-stored-bytes"
        ),
        pytest.param("other-release", "identical", 0, False, False, id="other-release"),
        pytest.param("own", "identical", 0, False, False, id="existing-own-copy"),
        pytest.param("identical", "identical", 0, True, True, id="commit-duplicate"),
        pytest.param("identical", None, 22, True, False, id="commit-unavailable-ci"),
    ],
)
def test_sign_release_signs_attested_installer_not_dirty_worktree(
    tmp_path: Path,
    stored_copy: str | None,
    published_copy: str | None,
    download_status: int,
    auto_commit: bool,
    omit_copy: bool,
) -> None:
    repo_dir = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    signed_inputs_dir = tmp_path / "signed-inputs"
    (repo_dir / "scripts").mkdir(parents=True)
    (repo_dir / "signatures").mkdir()
    bin_dir.mkdir()
    signed_inputs_dir.mkdir()

    (repo_dir / "scripts" / "sign-release.sh").write_text(
        SIGN_RELEASE_SCRIPT.read_text()
    )
    (repo_dir / "signatures" / "trusted-keys.txt").write_text(
        f"{TEST_FINGERPRINT} Test User\n"
    )
    (repo_dir / "install.sh").write_text("committed installer\n")
    (repo_dir / "README.md").write_text("release source\n")
    run_git(repo_dir, "init", "--initial-branch=main")
    run_git(repo_dir, "config", "commit.gpgsign", "false")
    run_git(repo_dir, "add", ".")
    run_git(repo_dir, "commit", "-m", "test: release source")
    commit = run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    run_git(repo_dir, "tag", "1.2.3")
    (repo_dir / "install.sh").write_text("dirty installer\n")

    manifest_path = repo_dir / "release-manifest-1.2.3.txt"
    manifest_path.write_text(
        f"# JoinMarket NG Release Manifest\n"
        f"## Git Commit\n"
        f"commit: {commit}\n"
        f"source_date_epoch: 1234567890\n"
    )
    manifest_bytes = manifest_path.read_bytes()
    signature_dir = repo_dir / "signatures" / "1.2.3"
    stored_path = None
    if stored_copy is not None:
        stored_dir = (
            repo_dir / "signatures" / "1.2.2"
            if stored_copy == "other-release"
            else signature_dir
        )
        stored_dir.mkdir(parents=True)
        stored_name = (
            f"{TEST_FINGERPRINT}-manifest.txt"
            if stored_copy == "own"
            else "BBBB-manifest.txt"
        )
        stored_path = stored_dir / stored_name
        stored_path.write_bytes(
            manifest_bytes + (b"\n" if stored_copy == "different" else b"")
        )
        run_git(repo_dir, "add", str(stored_path))
        run_git(repo_dir, "commit", "-m", "test: existing manifest")
    before_commit = run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    published_path = tmp_path / "published-manifest.txt"
    if published_copy is not None:
        published_path.write_bytes(
            manifest_bytes + (b"\n" if published_copy == "different" else b"")
        )
    curl_calls = tmp_path / "curl-calls"
    write_executable(
        bin_dir / "curl",
        textwrap.dedent(
            f"""#!/usr/bin/env bash
            set -euo pipefail
            printf '%s\\n' "$*" >> "{curl_calls}"
            output=""
            while [[ $# -gt 0 ]]; do
                if [[ "$1" == "-o" ]]; then
                    output="$2"
                    shift 2
                else
                    shift
                fi
            done
            if [[ -f "{published_path}" ]]; then
                cp "{published_path}" "$output"
            fi
            exit {download_status}
            """
        ),
    )

    write_executable(
        bin_dir / "gpg",
        textwrap.dedent(
            f"""#!/usr/bin/env bash
            set -euo pipefail
            if [[ "${{1:-}}" == "--fingerprint" ]]; then
                printf '1111 2222 3333 4444 5555  6666 7777 8888 9999 AAAA\\n'
                exit 0
            fi
            if [[ "${{1:-}}" == "--local-user" ]]; then
                output=""
                input=""
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        --output)
                            output="$2"
                            shift 2
                            ;;
                        *)
                            input="$1"
                            shift
                            ;;
                    esac
                done
                cp "$input" "{signed_inputs_dir}/$(basename "$output").input"
                : > "$output"
                exit 0
            fi
            if [[ "${{1:-}}" == "--verify" ]]; then
                exit 0
            fi
            exit 1
            """
        ),
    )
    write_executable(bin_dir / "jq", "#!/usr/bin/env bash\nexit 0\n")

    result = subprocess.run(
        [
            "bash",
            str(repo_dir / "scripts" / "sign-release.sh"),
            "1.2.3",
            "--manifest",
            str(manifest_path),
            "--key",
            "TESTKEY",
            "--no-reproduce",
            *([] if auto_commit else ["--no-push"]),
        ],
        cwd=repo_dir,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GIT_AUTHOR_NAME": "Test User",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test User",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        },
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (signature_dir / f"{TEST_FINGERPRINT}.sig").is_file()
    assert (signature_dir / f"{TEST_FINGERPRINT}.install.sh.sig").is_file()
    assert (
        signed_inputs_dir / f"{TEST_FINGERPRINT}.install.sh.sig.input"
    ).read_text() == "committed installer\n"
    assert (
        signed_inputs_dir / f"{TEST_FINGERPRINT}.sig.input"
    ).read_bytes() == manifest_bytes
    own_manifest = signature_dir / f"{TEST_FINGERPRINT}-manifest.txt"
    if omit_copy:
        assert not own_manifest.exists()
        assert "skipping duplicate local manifest copy" in result.stdout
        if not auto_commit:
            staging_line = next(
                line for line in result.stdout.splitlines() if "git add " in line
            )
            assert str(own_manifest) not in staging_line
    else:
        assert own_manifest.read_bytes() == manifest_bytes
    if stored_path is not None:
        assert stored_path.read_bytes() == manifest_bytes + (
            b"\n" if stored_copy == "different" else b""
        )
    assert curl_calls.exists() == (stored_copy == "identical")
    if curl_calls.exists():
        assert "--connect-timeout 5 --max-time 15" in curl_calls.read_text()
        assert (
            "/releases/download/1.2.3/release-manifest-1.2.3.txt"
            in curl_calls.read_text()
        )
    if auto_commit:
        changed_files = set(
            run_git(
                repo_dir, "diff", "--name-only", before_commit, "HEAD"
            ).stdout.splitlines()
        )
        expected_files = {
            f"signatures/1.2.3/{TEST_FINGERPRINT}.sig",
            f"signatures/1.2.3/{TEST_FINGERPRINT}.install.sh.sig",
        }
        if not omit_copy:
            expected_files.add(f"signatures/1.2.3/{TEST_FINGERPRINT}-manifest.txt")
        assert changed_files == expected_files
        assert run_git(repo_dir, "remote").stdout == ""


def test_sign_release_fails_before_signing_when_attested_installer_is_missing(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    gpg_calls = tmp_path / "gpg-calls"
    (repo_dir / "scripts").mkdir(parents=True)
    (repo_dir / "signatures").mkdir()
    bin_dir.mkdir()

    (repo_dir / "scripts" / "sign-release.sh").write_text(
        SIGN_RELEASE_SCRIPT.read_text()
    )
    (repo_dir / "signatures" / "trusted-keys.txt").write_text(
        f"{TEST_FINGERPRINT} Test User\n"
    )
    (repo_dir / "README.md").write_text("release source\n")
    run_git(repo_dir, "init", "--initial-branch=main")
    run_git(repo_dir, "add", ".")
    run_git(repo_dir, "commit", "-m", "test: release source")
    commit = run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    run_git(repo_dir, "tag", "1.2.3")

    manifest_path = repo_dir / "release-manifest-1.2.3.txt"
    manifest_path.write_text(f"commit: {commit}\n")

    write_executable(
        bin_dir / "gpg",
        textwrap.dedent(
            f"""#!/usr/bin/env bash
            if [[ "${{1:-}}" == "--fingerprint" ]]; then
                printf '1111 2222 3333 4444 5555  6666 7777 8888 9999 AAAA\\n'
                exit 0
            fi
            touch "{gpg_calls}"
            exit 1
            """
        ),
    )
    write_executable(bin_dir / "jq", "#!/usr/bin/env bash\nexit 0\n")

    result = subprocess.run(
        [
            "bash",
            str(repo_dir / "scripts" / "sign-release.sh"),
            "1.2.3",
            "--manifest",
            str(manifest_path),
            "--key",
            "TESTKEY",
            "--no-reproduce",
            "--no-push",
        ],
        cwd=repo_dir,
        text=True,
        capture_output=True,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        check=False,
    )

    assert result.returncode != 0
    assert (
        "Installer source install.sh is missing from manifest commit" in result.stdout
    )
    assert not gpg_calls.exists()


def test_sign_release_rejects_ci_manifest_from_different_commit(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    gpg_calls = tmp_path / "gpg-calls"
    (repo_dir / "scripts").mkdir(parents=True)
    (repo_dir / "signatures").mkdir()
    bin_dir.mkdir()

    (repo_dir / "scripts" / "sign-release.sh").write_text(
        SIGN_RELEASE_SCRIPT.read_text()
    )
    (repo_dir / "signatures" / "trusted-keys.txt").write_text(
        f"{TEST_FINGERPRINT} Test User\n"
    )
    (repo_dir / "install.sh").write_text("first installer\n")
    run_git(repo_dir, "init", "--initial-branch=main")
    run_git(repo_dir, "add", ".")
    run_git(repo_dir, "commit", "-m", "test: first release source")
    manifest_commit = run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    (repo_dir / "install.sh").write_text("tagged installer\n")
    run_git(repo_dir, "commit", "-am", "test: tagged release source")
    tagged_commit = run_git(repo_dir, "rev-parse", "HEAD").stdout.strip()
    run_git(repo_dir, "tag", "1.2.3")

    remote_manifest = tmp_path / "remote-manifest.txt"
    remote_manifest.write_text(f"commit: {manifest_commit}\n")
    write_executable(
        bin_dir / "curl",
        textwrap.dedent(
            f"""#!/usr/bin/env bash
            set -euo pipefail
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -o)
                        cp "{remote_manifest}" "$2"
                        exit 0
                        ;;
                    *)
                        shift
                        ;;
                esac
            done
            exit 1
            """
        ),
    )
    write_executable(
        bin_dir / "gpg",
        textwrap.dedent(
            f"""#!/usr/bin/env bash
            if [[ "${{1:-}}" == "--fingerprint" ]]; then
                printf '1111 2222 3333 4444 5555  6666 7777 8888 9999 AAAA\\n'
                exit 0
            fi
            touch "{gpg_calls}"
            exit 1
            """
        ),
    )
    write_executable(bin_dir / "jq", "#!/usr/bin/env bash\nexit 0\n")

    result = subprocess.run(
        [
            "bash",
            str(repo_dir / "scripts" / "sign-release.sh"),
            "1.2.3",
            "--key",
            "TESTKEY",
            "--no-reproduce",
            "--no-push",
        ],
        cwd=repo_dir,
        text=True,
        capture_output=True,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        check=False,
    )

    assert result.returncode != 0
    assert "Downloaded manifest commit does not match tag 1.2.3." in result.stdout
    assert manifest_commit in result.stdout
    assert tagged_commit in result.stdout
    assert not gpg_calls.exists()


def test_release_workflow_uploads_the_attested_installer() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yaml").read_text()

    assert 'git show "${COMMIT_SHA}:install.sh" > install.sh' in workflow
    assert (
        "gh release upload ${VERSION} release-manifest-${VERSION}.txt install.sh --clobber"
        in workflow
    )
