"""Smoke tests for the installed wallet tools in the maker Docker image."""

from __future__ import annotations

import os
import subprocess

import pytest

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def maker_image() -> str:
    image = os.environ.get("MAKER_IMAGE", "")
    if not image:
        pytest.fail("Set MAKER_IMAGE to the maker image to test")
    return image


@pytest.mark.parametrize(
    ("command", "expected_cli"),
    [
        pytest.param((), "jm-maker", id="default-command"),
        pytest.param(("jm-maker", "--help"), "jm-maker", id="maker"),
        pytest.param(("jm-wallet", "--help"), "jm-wallet", id="wallet"),
        pytest.param(("jm-taker", "--help"), "jm-taker", id="taker"),
        pytest.param(("jm-tumbler", "--help"), "jm-tumbler", id="tumbler"),
    ],
)
def test_maker_image_wallet_tools(
    maker_image: str, command: tuple[str, ...], expected_cli: str
) -> None:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            maker_image,
            *command,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert f"Usage: {expected_cli}" in output, output
