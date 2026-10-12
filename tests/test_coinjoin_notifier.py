from __future__ import annotations

from contextlib import nullcontext
from email.message import Message
import importlib.util
import json
import logging
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest


def _load_notifier() -> ModuleType:
    script_path = Path(__file__).parents[1] / "scripts" / "coinjoin_notifier.py"
    spec = importlib.util.spec_from_file_location("coinjoin_notifier", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_notification_uses_neutral_amount() -> None:
    notifier = _load_notifier()

    _title, message, _priority = notifier.create_notification_message(
        {
            "role": "send",
            "success": "True",
            "confirmations": "0",
            "amount": "666",
            "cj_amount": "0",
        }
    )

    assert "(666 sats)" in message


def test_notification_falls_back_to_legacy_cj_amount() -> None:
    notifier = _load_notifier()

    _title, message, _priority = notifier.create_notification_message(
        {
            "role": "maker",
            "success": "True",
            "confirmations": "1",
            "cj_amount": "777",
        }
    )

    assert "(777 sats)" in message


def test_gotify_notification_sends_token_in_header_and_payload() -> None:
    notifier = _load_notifier()
    token = "canary-gotify-token"

    with (
        patch.object(notifier, "GOTIFY_URL", "https://gotify.example.test"),
        patch.object(notifier, "GOTIFY_TOKEN", token),
        patch.object(notifier, "urlopen", return_value=nullcontext()) as urlopen_mock,
    ):
        assert notifier.send_gotify_notification(
            "CoinJoin complete", "Sent 123 sats", 7
        )

    assert not hasattr(notifier, "subprocess")
    request = urlopen_mock.call_args.args[0]
    request_headers = {key.lower(): value for key, value in request.header_items()}
    assert request.full_url == "https://gotify.example.test/message"
    assert token not in request.full_url
    assert request.get_method() == "POST"
    assert request_headers["x-gotify-key"] == token
    assert request_headers["content-type"] == "application/json"
    assert json.loads(request.data) == {
        "title": "CoinJoin complete",
        "message": "Sent 123 sats",
        "priority": 7,
    }
    assert urlopen_mock.call_args.kwargs == {"timeout": 10}


@pytest.mark.parametrize(
    "error",
    [
        HTTPError(
            "https://gotify.example.test/message?token=canary-gotify-token",
            500,
            "Internal Server Error",
            Message(),
            None,
        ),
        URLError("connection failed"),
    ],
)
def test_gotify_notification_failure_does_not_log_token(
    error: OSError, caplog: pytest.LogCaptureFixture
) -> None:
    notifier = _load_notifier()
    token = "canary-gotify-token"

    with (
        patch.object(notifier, "GOTIFY_URL", "https://gotify.example.test"),
        patch.object(notifier, "GOTIFY_TOKEN", token),
        patch.object(notifier, "urlopen", side_effect=error),
    ):
        with caplog.at_level(logging.ERROR, logger=notifier.logger.name):
            assert not notifier.send_gotify_notification(
                "CoinJoin complete", "Sent 123 sats", 7
            )

    assert caplog.messages == ["Failed to send Gotify notification"]
    assert token not in caplog.text
