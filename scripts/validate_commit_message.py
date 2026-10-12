#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from changelog_commit_utils import ALLOWED_PREFIXES, parse_commit

PROJECT_ROOT = Path(__file__).parent.parent
DELIMITER = "---COMMIT-DELIMITER---"
CHANGELOG_TYPES = {"feat", "fix"}


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str]


def normalize_commit_text(text: str) -> str:
    """Remove git comment lines from commit message text."""
    lines = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def split_subject_and_body(message: str) -> tuple[str, str]:
    lines = message.splitlines()
    subject = ""
    subject_index = -1

    for index, line in enumerate(lines):
        if line.strip():
            subject = line.strip()
            subject_index = index
            break

    if not subject:
        return "", ""

    body = "\n".join(lines[subject_index + 1 :]).strip()
    return subject, body


def validate_message(message: str, source_label: str) -> ValidationResult:
    normalized = normalize_commit_text(message)
    if not normalized:
        return ValidationResult(ok=True, errors=[])

    subject, body = split_subject_and_body(normalized)
    parsed = parse_commit(subject, body)

    if parsed is None:
        stripped = subject.strip()
        if stripped.startswith(ALLOWED_PREFIXES):
            return ValidationResult(ok=True, errors=[])

        return ValidationResult(
            ok=False,
            errors=[
                (
                    f"{source_label}: commit title must follow Conventional Commits "
                    "(<type>(<scope>)?: <description>)"
                )
            ],
        )

    errors: list[str] = []

    if parsed.type in CHANGELOG_TYPES and not parsed.changelog_entries:
        errors.append(
            f"{source_label}: '{parsed.type}' commits must include at least one "
            "'Changelog: ...' trailer in the commit body/footer"
        )

    return ValidationResult(ok=not errors, errors=errors)


def run_git_log(rev_range: str) -> str:
    result = subprocess.run(
        [
            "git",
            "log",
            "--reverse",
            "--format=%H%n%s%n%b" + DELIMITER,
            rev_range,
        ],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or f"git log failed for range {rev_range}"
        )
    return result.stdout


def validate_rev_range(rev_range: str) -> ValidationResult:
    output = run_git_log(rev_range)
    errors: list[str] = []

    for block in output.split(DELIMITER):
        text = block.strip()
        if not text:
            continue

        lines = text.split("\n", 2)
        if len(lines) < 2:
            continue

        commit_hash = lines[0][:8]
        subject = lines[1]
        body = lines[2] if len(lines) > 2 else ""
        message = f"{subject}\n\n{body}".strip()

        result = validate_message(message, source_label=f"commit {commit_hash}")
        errors.extend(result.errors)

    return ValidationResult(ok=not errors, errors=errors)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate Conventional Commits and require Changelog trailers on feat/fix commits."
        )
    )

    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument(
        "--commit-msg-file",
        dest="commit_msg_file_opt",
        help="Path to commit message file",
    )
    mode.add_argument("--message", help="Commit message text to validate")
    mode.add_argument("--rev-range", help="Git revision range to validate")
    parser.add_argument(
        "commit_msg_file", nargs="?", help="Positional commit message file path"
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.rev_range:
        result = validate_rev_range(args.rev_range)
    elif args.message:
        result = validate_message(args.message, source_label="message")
    else:
        file_arg = args.commit_msg_file_opt or args.commit_msg_file
        if not file_arg:
            print(
                "Error: provide one of --rev-range, --message, --commit-msg-file, or a positional message file"
            )
            sys.exit(2)

        commit_text = Path(file_arg).read_text(encoding="utf-8")
        result = validate_message(commit_text, source_label=file_arg)

    if not result.ok:
        print("Commit message validation failed:")
        for error in result.errors:
            print(f"- {error}")
        print()
        print("Required for feat/fix commits:")
        print("  Changelog: <human-friendly changelog entry>")
        sys.exit(1)


if __name__ == "__main__":
    main()
