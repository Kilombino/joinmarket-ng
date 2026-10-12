"""Tests for instance-scoped Docker Compose test isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.e2e import docker_utils


def test_instance_scoped_compose_override_resolution(
    tmp_path: Path, monkeypatch
) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.touch()
    override = (
        tmp_path
        / "tmp"
        / "parallel-tests"
        / "i3"
        / "docker-compose.reference-maker.override.yml"
    )
    override.parent.mkdir(parents=True)
    override.touch()
    monkeypatch.setattr(docker_utils, "get_compose_file", lambda: compose_file)
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "jmpt-i3-reference-maker")

    assert docker_utils.get_compose_override_file() == override


def test_unchecked_commands_report_missing_docker(monkeypatch) -> None:
    """Import-time service probes must not raise when Docker is not installed."""

    def missing_docker(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(docker_utils.subprocess, "run", missing_docker)

    compose = docker_utils.run_compose_cmd(["ps", "-q", "jam"], check=False)
    exec_result = docker_utils.run_container_cmd("jam", ["true"])

    assert compose.returncode == 127
    assert compose.stdout == ""
    assert exec_result.returncode == 127


def test_checked_compose_command_still_raises_without_docker(monkeypatch) -> None:
    def missing_docker(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(docker_utils.subprocess, "run", missing_docker)

    with pytest.raises(FileNotFoundError):
        docker_utils.run_compose_cmd(["ps"], check=True)
