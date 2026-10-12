from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from pathlib import Path

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


def test_sign_release_signs_attested_installer_not_dirty_worktree(
    tmp_path: Path,
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
            "--no-push",
        ],
        cwd=repo_dir,
        text=True,
        capture_output=True,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    signature_dir = repo_dir / "signatures" / "1.2.3"
    assert (signature_dir / f"{TEST_FINGERPRINT}.sig").is_file()
    assert (signature_dir / f"{TEST_FINGERPRINT}.install.sh.sig").is_file()
    assert (
        signed_inputs_dir / f"{TEST_FINGERPRINT}.install.sh.sig.input"
    ).read_text() == "committed installer\n"


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
