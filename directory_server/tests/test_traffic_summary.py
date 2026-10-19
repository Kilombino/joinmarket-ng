"""Periodic traffic summary replaces per-message relay logging at INFO."""

from __future__ import annotations

import pytest
from jmcore.models import NetworkType
from jmcore.settings import DirectoryServerSettings
from loguru import logger

from directory_server.server import DirectoryServer


@pytest.fixture
def server() -> DirectoryServer:
    settings = DirectoryServerSettings(host="127.0.0.1", port=0, max_peers=10)
    return DirectoryServer(settings, NetworkType.MAINNET, "J5TestNickOOOOOO")


def _capture() -> tuple[list[tuple[str, str]], int]:
    records: list[tuple[str, str]] = []
    handler = logger.add(
        lambda m: records.append((m.record["level"].name, str(m.record["message"]))),
        level="DEBUG",
    )
    return records, handler


def test_summary_is_silent_without_traffic(server: DirectoryServer) -> None:
    records, handler = _capture()
    try:
        server.log_traffic_summary()
    finally:
        logger.remove(handler)
    assert records == []


def test_summary_reports_window_counts_once(server: DirectoryServer) -> None:
    counts = server.message_router._privmsg_counts
    counts.relayed = 7
    counts.unknown_target = 3
    # Rate limiter violations are cumulative; the summary reports the delta.
    server.rate_limiter._violation_counts["conn-1"] = 5

    records, handler = _capture()
    try:
        server.log_traffic_summary()
        server.rate_limiter._violation_counts["conn-1"] = 9
        server.log_traffic_summary()
    finally:
        logger.remove(handler)

    assert [level for level, _ in records] == ["INFO", "INFO"]
    first, second = (message for _, message in records)
    assert "relayed=7" in first and "unknown_target=3" in first and "rate_limit_drops=5" in first
    assert "relayed=0" in second and "rate_limit_drops=4" in second
