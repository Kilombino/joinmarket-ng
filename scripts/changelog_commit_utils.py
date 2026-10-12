#!/usr/bin/env python3
from __future__ import annotations

import re
from dataclasses import dataclass

CONVENTIONAL_COMMIT_PATTERN = re.compile(
    r"^(?P<type>[a-z]+)"
    r"(?:\((?P<scope>[^)]+)\))?"
    r"(?P<breaking>!)?"
    r":\s*"
    r"(?P<description>.+)$",
    re.IGNORECASE,
)

BREAKING_CHANGE_PATTERN = re.compile(
    r"^BREAKING[ -]CHANGE:\s*(?P<value>.+)$",
    re.IGNORECASE,
)

CHANGELOG_TRAILER_PATTERN = re.compile(
    r"^Changelog:\s*(?P<value>.*)$",
    re.IGNORECASE,
)

ALLOWED_PREFIXES = (
    "Merge ",
    "Revert ",
    "Pull request ",
    "fixup!",
    "squash!",
    "amend!",
)


@dataclass(frozen=True)
class ParsedCommit:
    type: str
    scope: str | None
    description: str
    is_breaking: bool
    changelog_entries: list[str]


def has_allowed_prefix(subject: str) -> bool:
    return subject.startswith(ALLOWED_PREFIXES)


def parse_changelog_trailers(body: str) -> list[str]:
    """Extract Changelog trailers from commit body/footer.

    Supports one or more trailer lines in git-trailer style:

      Changelog: first line
        continuation line

    """
    entries: list[list[str]] = []

    for raw_line in body.splitlines():
        line = raw_line.rstrip()
        trailer_match = CHANGELOG_TRAILER_PATTERN.match(line)

        if trailer_match:
            value = trailer_match.group("value").strip()
            entries.append([value] if value else [])
            continue

        if entries and (line.startswith(" ") or line.startswith("\t")):
            continuation = line.strip()
            if continuation:
                entries[-1].append(continuation)

    flattened: list[str] = []
    for chunks in entries:
        value = " ".join(chunks).strip()
        if value:
            flattened.append(value)

    return flattened


def parse_commit(subject: str, body: str) -> ParsedCommit | None:
    if has_allowed_prefix(subject):
        return None

    match = CONVENTIONAL_COMMIT_PATTERN.match(subject)
    if not match:
        return None

    commit_type = match.group("type").lower()
    scope = match.group("scope")
    description = match.group("description").strip()
    is_breaking = bool(match.group("breaking"))

    for line in body.splitlines():
        if BREAKING_CHANGE_PATTERN.match(line.strip()):
            is_breaking = True
            break

    changelog_entries = parse_changelog_trailers(body)

    return ParsedCommit(
        type=commit_type,
        scope=scope,
        description=description,
        is_breaking=is_breaking,
        changelog_entries=changelog_entries,
    )
