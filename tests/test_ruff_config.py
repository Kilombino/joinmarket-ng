from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _lint_codes(filename: str, source: str) -> set[str]:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--no-cache",
            "--output-format",
            "json",
            "--stdin-filename",
            str(REPO_ROOT / filename),
            "-",
        ],
        input=source,
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )
    assert result.returncode in (0, 1), result.stderr
    return {diagnostic["code"] for diagnostic in json.loads(result.stdout)}


@pytest.mark.parametrize("directory", ["scripts", "tests", "flatpak"])
def test_root_lint_policy_preserves_pre_016_defaults(directory: str) -> None:
    codes = _lint_codes(
        f"{directory}/lint_policy_probe.py",
        "import os\n\ndef probe(value):\n    unused = 1\n    return value\n",
    )

    assert codes == {"F401", "F841"}


def test_component_lint_policy_remains_independent() -> None:
    codes = _lint_codes(
        "orderbook_watcher/src/orderbook_watcher/lint_policy_probe.py",
        "def probe(value):\n    unused = 1\n    return value\n",
    )

    assert {"ANN001", "ANN201", "F841"} <= codes


def test_orderbook_argument_count_exemptions_remain_effective() -> None:
    codes = _lint_codes(
        "orderbook_watcher/src/orderbook_watcher/lint_policy_probe.py",
        "def probe(a: int, b: int, c: int, d: int, e: int, f: int) -> int:\n"
        "    return a + b + c + d + e + f\n",
    )

    assert codes == set()
