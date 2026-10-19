import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jmcore.models import NetworkType, Offer, OfferType

from maker.bot import MakerBot
from maker.config import MakerConfig
from maker.fidelity import FidelityBondInfo


@pytest.fixture
def mock_wallet():
    wallet = MagicMock()
    wallet.mixdepth_count = 5
    wallet.utxo_cache = {}
    return wallet


@pytest.fixture
def mock_backend():
    return MagicMock()


@pytest.fixture
def config():
    return MakerConfig(
        mnemonic="test " * 12,
        directory_servers=["localhost:5222"],
        network=NetworkType.REGTEST,
    )


@pytest.fixture
def maker_bot(mock_wallet, mock_backend, config):
    bot = MakerBot(
        wallet=mock_wallet,
        backend=mock_backend,
        config=config,
    )
    bot.running = True
    return bot


@pytest.fixture
def sample_offer(maker_bot):
    return Offer(
        counterparty=maker_bot.nick,
        oid=0,
        ordertype=OfferType.SW0_RELATIVE,
        minsize=100_000,
        maxsize=10_000_000,
        txfee=1000,
        cjfee="0.0003",
        fidelity_bond_value=0,
    )


@pytest.mark.asyncio
async def test_reconnect_does_not_announce_bond_publicly(
    maker_bot, sample_offer, test_private_key, test_pubkey
):
    """
    Public reconnect re-announcements MUST NOT include the fidelity bond
    proof. The bond is delivered via privmsg in response to !orderbook,
    matching the reference protocol
    (jmdaemon/message_channel.py::MessageChannelCollection.announce_orders,
    which asserts `fidelity_bond_proof_msg is None` for public broadcasts).

    Regression test against the prior behavior where the reconnect path used
    include_bond=True, leaking the bond UTXO to every passive observer of
    the directory pit on every reconnect.
    """
    bot = maker_bot
    bot.current_offers = [sample_offer]

    bot.fidelity_bond = FidelityBondInfo(
        txid="ab" * 32,
        vout=0,
        value=100_000_000,
        locktime=800000,
        confirmation_time=1000,
        bond_value=50_000,
        pubkey=test_pubkey,
        private_key=test_private_key,
    )

    node_id = "localhost:5222"
    bot.directory_clients = {}
    bot._directory_reconnect_attempts = {node_id: 0}

    mock_client = MagicMock()
    mock_client.send_public_message = AsyncMock(return_value=None)

    bot._connect_to_directory = AsyncMock(return_value=(node_id, mock_client))

    with (
        patch("maker.background_tasks.get_notifier") as mock_notifier,
        patch.object(
            bot, "_format_offer_announcement", wraps=bot._format_offer_announcement
        ) as mock_format,
        # One reconnect pass right after the initial delay, then stop.
        patch("asyncio.sleep", side_effect=[0, asyncio.CancelledError()]),
    ):
        mock_notifier.return_value = MagicMock()
        mock_notifier.return_value.notify_directory_reconnect = AsyncMock()
        mock_notifier.return_value.notify_all_directories_reconnected = AsyncMock()

        try:
            await bot._periodic_directory_reconnect()
        except asyncio.CancelledError:
            pass

        assert mock_format.called, "_format_offer_announcement was not called during reconnect"

        # Every call from the reconnect path must use include_bond=False.
        bond_calls = [c for c in mock_format.call_args_list if c.kwargs.get("include_bond") is True]
        assert bond_calls == [], (
            f"Reconnect announcement leaked the fidelity bond proof publicly "
            f"(include_bond=True in {len(bond_calls)} call(s))."
        )

        # And no message actually broadcast contained a !tbond tag.
        for call in mock_client.send_public_message.call_args_list:
            (msg,) = call.args
            assert "!tbond" not in msg, (
                f"Public reconnect message must not contain !tbond, got: {msg!r}"
            )


@pytest.mark.asyncio
async def test_periodic_reconnect_dials_directories_concurrently(
    mock_wallet, mock_backend, sample_offer
):
    """One unreachable directory must not delay reconnection to the others.

    A dead onion costs the full Tor connect timeout, so sequential dialing
    would hold healthy directories behind every dead one on each pass.
    """
    config = MakerConfig(
        mnemonic="test " * 12,
        directory_servers=["dead.onion:5222", "alive.onion:5222"],
        network=NetworkType.REGTEST,
    )
    bot = MakerBot(wallet=mock_wallet, backend=mock_backend, config=config)
    bot.running = True
    bot.directory_clients = {}
    bot.current_offers = [sample_offer]

    dead_started = asyncio.Event()
    release_dead = asyncio.Event()
    alive_client = MagicMock()
    announced = asyncio.Event()
    alive_client.send_public_message = AsyncMock(side_effect=lambda *_: announced.set())

    async def connect(dir_server: str):
        if dir_server.startswith("dead"):
            dead_started.set()
            await release_dead.wait()
            return None
        # The healthy directory only answers once the dead one is already
        # blocked, which proves the two dials overlap.
        await dead_started.wait()
        return ("alive.onion:5222", alive_client)

    bot._connect_to_directory = AsyncMock(side_effect=connect)
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        # The first pass runs right after the initial delay, not an interval later.
        sleeps.append(delay)
        if len(sleeps) > 1:
            raise asyncio.CancelledError()

    with (
        patch("maker.background_tasks.get_notifier") as mock_notifier,
        patch("maker.background_tasks.asyncio.sleep", side_effect=fake_sleep),
    ):
        mock_notifier.return_value = MagicMock()
        mock_notifier.return_value.notify_directory_reconnect = AsyncMock()
        mock_notifier.return_value.notify_all_directories_reconnected = AsyncMock()
        task = asyncio.create_task(bot._periodic_directory_reconnect())
        await asyncio.wait_for(dead_started.wait(), timeout=2.0)
        # The healthy directory is installed and announced while the dead
        # dial is still blocked; offers must not wait on a Tor timeout.
        await asyncio.wait_for(announced.wait(), timeout=2.0)
        assert "alive.onion:5222" in bot.directory_clients
        assert bot._directory_reconnect_attempts.get("dead.onion:5222") is None
        release_dead.set()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except asyncio.CancelledError:
            pass

    assert sleeps[0] == 60.0
    assert bot._directory_reconnect_attempts.get("dead.onion:5222") == 1
