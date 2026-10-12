from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "directory_server" / "docker-compose.yml"


def test_directory_compose_refuses_to_start_without_nick_auth_identity() -> None:
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    service = compose["services"]["directory_server"]
    command = service["command"]
    script = command[2].replace("$$", "$")
    environment = os.environ.copy()
    environment.pop("DIRECTORY_SERVER__NICK_AUTH_DIRECTORY_ID", None)

    result = subprocess.run(
        [*command[:2], script],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode != 0
    assert "DIRECTORY_SERVER__NICK_AUTH_DIRECTORY_ID must be set" in result.stderr
