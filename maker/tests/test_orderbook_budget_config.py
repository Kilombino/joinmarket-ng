"""Public configuration and runtime wiring for aggregate response budgets."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from jmcore.models import NetworkType
from jmcore.settings import JoinMarketSettings, MakerSettings
from pydantic import ValidationError

from maker.bot import MakerBot
from maker.cli import build_maker_config
from maker.config import MakerConfig

TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

BURST_FIELDS = ["directory_orderbook_response_burst", "direct_orderbook_response_burst"]
REFILL_FIELDS = [
    "directory_orderbook_response_refill_per_second",
    "direct_orderbook_response_refill_per_second",
]
DEFAULTS = {
    "directory_orderbook_response_burst": 200,
    "directory_orderbook_response_refill_per_second": 20.0,
    "direct_orderbook_response_burst": 20,
    "direct_orderbook_response_refill_per_second": 2.0,
}


@pytest.mark.parametrize("field", BURST_FIELDS)
@pytest.mark.parametrize("value", [0, -1, 1.5, 2**53, 10**400])
def test_public_models_reject_invalid_bursts(field: str, value: int | float) -> None:
    for model, base in [(MakerSettings, {}), (MakerConfig, {"mnemonic": TEST_MNEMONIC})]:
        with pytest.raises(ValidationError, match=field):
            model(**base, **{field: value})


@pytest.mark.parametrize("field", BURST_FIELDS)
@pytest.mark.parametrize("value", [1, 2**53 - 1])
def test_public_models_accept_burst_boundaries(field: str, value: int) -> None:
    settings = MakerSettings(**{field: value})
    config = MakerConfig(mnemonic=TEST_MNEMONIC, **{field: value})
    assert getattr(settings, field) == value
    assert getattr(config, field) == value


@pytest.mark.parametrize("field", REFILL_FIELDS)
@pytest.mark.parametrize("value", [0.0, -1.0, float("nan"), float("inf"), -float("inf")])
def test_public_models_reject_invalid_refill_rates(field: str, value: float) -> None:
    for model, base in [(MakerSettings, {}), (MakerConfig, {"mnemonic": TEST_MNEMONIC})]:
        with pytest.raises(ValidationError, match=field):
            model(**base, **{field: value})


def test_existing_configurations_keep_default_budgets() -> None:
    settings = MakerSettings()
    config = MakerConfig(mnemonic=TEST_MNEMONIC)
    for field, expected in DEFAULTS.items():
        assert getattr(settings, field) == expected
        assert getattr(config, field) == expected


def test_standalone_builder_passes_all_custom_budgets() -> None:
    values = {
        "directory_orderbook_response_burst": 400,
        "directory_orderbook_response_refill_per_second": 40.5,
        "direct_orderbook_response_burst": 50,
        "direct_orderbook_response_refill_per_second": 5.5,
    }
    settings = JoinMarketSettings(maker=values)
    config = build_maker_config(settings=settings, mnemonic=TEST_MNEMONIC, passphrase="")
    for field, expected in values.items():
        assert getattr(config, field) == expected


def test_custom_bot_budgets_exhaust_and_refill_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr("maker.rate_limiting.time.monotonic", lambda: now[0])
    config = MakerConfig(
        mnemonic=TEST_MNEMONIC,
        network=NetworkType.REGTEST,
        directory_servers=["localhost:5222"],
        directory_orderbook_response_burst=3,
        directory_orderbook_response_refill_per_second=2.0,
        direct_orderbook_response_burst=2,
        direct_orderbook_response_refill_per_second=4.0,
    )
    wallet = MagicMock(mixdepth_count=5, utxo_cache={})
    bot = MakerBot(wallet=wallet, backend=MagicMock(), config=config)
    directory = bot._directory_orderbook_response_limiter
    direct = bot._direct_orderbook_response_limiter

    assert (directory.burst, directory.refill_per_second) == (3, 2.0)
    assert (direct.burst, direct.refill_per_second) == (2, 4.0)
    assert all(directory.try_consume() for _ in range(3))
    assert directory.try_consume() is False
    assert all(direct.try_consume() for _ in range(2))
    assert direct.try_consume() is False

    now[0] += 0.25
    assert directory.try_consume() is False
    assert direct.try_consume() is True
    assert direct.try_consume() is False
    now[0] += 0.25
    assert directory.try_consume() is True
    assert directory.try_consume() is False
    assert direct.try_consume() is True

    # Idle time cannot accumulate more capacity than the configured burst.
    now[0] += 100.0
    assert all(directory.try_consume() for _ in range(3))
    assert directory.try_consume() is False
    assert all(direct.try_consume() for _ in range(2))
    assert direct.try_consume() is False
