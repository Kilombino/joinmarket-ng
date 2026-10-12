"""
End-to-end test for the Layer 4 deposit-address verifier.

Background
==========

Prior to commit 2568367b, ``jm-wallet info`` would propose a new deposit
address using only the in-memory ``addresses_with_history`` set populated
by the bulk sync. If the bulk walk was incomplete (RPC truncation,
bitcoind socket drop mid-pagination, persisted store predating a node
reindex, etc.), a previously-funded address could be re-proposed,
linking the new sender to the prior coin's history.

The fix verifies each candidate address against bitcoind via
``getreceivedbyaddress addr 0`` immediately before handing it out
(``DescriptorWalletBackend.address_has_history``).

This test verifies that method against a real regtest node:

  1. Funding a receive address (confirmed) -> ``address_has_history``
     returns ``True``.
  2. Funding a receive address that is still in the mempool ->
     ``address_has_history`` returns ``True`` (minconf=0 is critical;
     even a mempool funding leaks privacy on reuse).
  3. A freshly generated, never-funded address ->
     ``address_has_history`` returns ``False``.
  4. RPC failure (closed client) -> returns ``None`` so callers can
     degrade gracefully rather than block or false-fail.

Without this defense, the verifier could silently accept funded
addresses and the bulk-sync incompleteness would translate directly
into a privacy leak.

Requires: docker compose up -d (the default ``jm-bitcoin`` regtest node).
"""

from __future__ import annotations

import asyncio
import secrets
from typing import Any

import httpx
import pytest
from jmwallet.backends.descriptor_wallet import DescriptorWalletBackend

from tests.e2e.docker_utils import run_compose_cmd

pytestmark = pytest.mark.e2e


_RPC_TIMEOUT = 60.0
_WALLET_NOTIFICATION_TIMEOUT = 10.0


async def _rpc(
    cfg: dict[str, str],
    method: str,
    params: list[Any] | None = None,
    wallet: str | None = None,
) -> Any:
    url = cfg["rpc_url"].rstrip("/")
    if wallet:
        url = f"{url}/wallet/{wallet}"
    payload = {
        "jsonrpc": "1.0",
        "id": "jmng-deposit-verify",
        "method": method,
        "params": params or [],
    }
    async with httpx.AsyncClient(timeout=_RPC_TIMEOUT) as client:
        response = await client.post(
            url, auth=(cfg["rpc_user"], cfg["rpc_password"]), json=payload
        )
    data = response.json()
    if data.get("error"):
        raise RuntimeError(f"{method} RPC error: {data['error']}")
    return data.get("result")


async def _ensure_wallet(cfg: dict[str, str], name: str) -> None:
    wallets = await _rpc(cfg, "listwallets")
    if name in wallets:
        return
    listed = await _rpc(cfg, "listwalletdir")
    if any(w.get("name") == name for w in listed.get("wallets", [])):
        await _rpc(cfg, "loadwallet", [name])
        return
    await _rpc(cfg, "createwallet", [name])


async def _wait_for_wallet_receipt(
    cfg: dict[str, str], wallet: str, address: str
) -> Any:
    """Wait for Core's receiving wallet to process a newly broadcast transaction."""
    deadline = asyncio.get_running_loop().time() + _WALLET_NOTIFICATION_TIMEOUT
    received: Any = 0
    while asyncio.get_running_loop().time() < deadline:
        received = await _rpc(cfg, "getreceivedbyaddress", [address, 0], wallet=wallet)
        if float(received) > 0:
            return received
        await asyncio.sleep(0.05)
    return received


@pytest.mark.asyncio
async def test_address_has_history_against_real_bitcoind(
    bitcoin_rpc_config: dict[str, str],
) -> None:
    """
    Cover the truth table of ``DescriptorWalletBackend.address_has_history``
    against a real regtest node.

    This is the privacy-critical primitive: if it ever fails to flag a
    funded address as "has history", the picker
    ``get_next_safe_deposit_address`` will hand that address to the next
    sender, leaking the link.
    """
    cfg = bitcoin_rpc_config
    suffix = secrets.token_hex(4)
    miner_wallet = f"jmng_addr_verifier_miner_{suffix}"
    test_wallet = f"jmng_addr_verifier_test_{suffix}"

    await _ensure_wallet(cfg, miner_wallet)
    await _ensure_wallet(cfg, test_wallet)

    try:
        # Fund the miner wallet so it can pay.
        miner_addr = await _rpc(
            cfg, "getnewaddress", ["", "bech32"], wallet=miner_wallet
        )
        info = await _rpc(cfg, "getwalletinfo", wallet=miner_wallet)
        if info.get("balance", 0) < 1.0:
            try:
                # Preferred: fund from test-funder (no coinbase mining needed).
                await _rpc(
                    cfg, "sendtoaddress", [miner_addr, 2.0], wallet="test-funder"
                )
                await _rpc(
                    cfg, "generatetoaddress", [1, miner_addr], wallet=miner_wallet
                )
            except Exception:
                # Fallback: mine 110 coinbase blocks (may yield 0 BTC at zero subsidy).
                await _rpc(
                    cfg, "generatetoaddress", [110, miner_addr], wallet=miner_wallet
                )

        # Three test addresses from the test wallet (so Core tracks
        # them under that wallet and getreceivedbyaddress works).
        addr_confirmed = await _rpc(
            cfg, "getnewaddress", ["", "bech32"], wallet=test_wallet
        )
        addr_mempool = await _rpc(
            cfg, "getnewaddress", ["", "bech32"], wallet=test_wallet
        )
        addr_unused = await _rpc(
            cfg, "getnewaddress", ["", "bech32"], wallet=test_wallet
        )

        backend = DescriptorWalletBackend(
            rpc_url=cfg["rpc_url"],
            rpc_user=cfg["rpc_user"],
            rpc_password=cfg["rpc_password"],
            wallet_name=test_wallet,
        )
        backend._wallet_loaded = True

        try:
            # Case 1: never funded. The verifier MUST report False so
            # the picker is allowed to hand out fresh addresses.
            assert await backend.address_has_history(addr_unused) is False, (
                "verifier flagged a never-funded address as having history; "
                "this would cause the picker to walk past every clean address "
                "and exhaust the descriptor range"
            )

            # Case 2: fund and confirm. The verifier MUST report True.
            await _rpc(
                cfg,
                "sendtoaddress",
                [addr_confirmed, 0.001],
                wallet=miner_wallet,
            )
            await _rpc(cfg, "generatetoaddress", [1, miner_addr], wallet=miner_wallet)
            assert await backend.address_has_history(addr_confirmed) is True, (
                "PRIVACY REGRESSION: verifier failed to detect a confirmed "
                "incoming payment to address used in a prior deposit; "
                "Layer 4b cannot guard against reuse"
            )

            # Case 3: fund without confirming (mempool only). The
            # verifier MUST still report True. minconf=0 is the
            # critical flag; a mempool-only funding still leaks the
            # link to a blockchain observer once the tx confirms.
            # The compose miner consumes the mempool every ten seconds. Stop it
            # so this case actually verifies an unconfirmed transaction.
            stop_miner = run_compose_cmd(["stop", "miner"], check=False)
            assert stop_miner.returncode == 0, stop_miner.stderr
            try:
                funding_txid = str(
                    await _rpc(
                        cfg,
                        "sendtoaddress",
                        [addr_mempool, 0.001],
                        wallet=miner_wallet,
                    )
                )
                mempool_entry = await _rpc(cfg, "getmempoolentry", [funding_txid])

                # Multiwallet notifications are asynchronous. Wait until the
                # receiving wallet sees the transaction before testing the backend.
                unconf = await _wait_for_wallet_receipt(cfg, test_wallet, addr_mempool)
                lru = await _rpc(
                    cfg,
                    "listunspent",
                    [0, 9999999, [addr_mempool]],
                    wallet=test_wallet,
                )
                assert float(unconf) > 0, (
                    "Core did not expose the mempool funding to the receiving wallet; "
                    f"txid={funding_txid}, mempool_entry={mempool_entry}, "
                    f"getreceivedbyaddress={unconf}, listunspent={lru}"
                )
                assert await backend.address_has_history(addr_mempool) is True, (
                    "PRIVACY REGRESSION: verifier missed a wallet-visible mempool funding; "
                    "getreceivedbyaddress must be called with minconf=0 or the "
                    "picker will reuse addresses that are about to confirm. "
                    f"txid={funding_txid}; "
                    f"Core direct getreceivedbyaddress({addr_mempool},0)={unconf}; "
                    f"listunspent 0={lru}"
                )
            finally:
                start_miner = run_compose_cmd(["start", "miner"], check=False)
                assert start_miner.returncode == 0, start_miner.stderr
        finally:
            await backend.close()

        # Case 4: RPC failure -> None. Close the backend's HTTP client
        # to force a connection error and confirm graceful degradation.
        broken_backend = DescriptorWalletBackend(
            rpc_url="http://127.0.0.1:1/",  # nothing listening
            rpc_user=cfg["rpc_user"],
            rpc_password=cfg["rpc_password"],
            wallet_name=test_wallet,
        )
        broken_backend._wallet_loaded = True
        try:
            result = await broken_backend.address_has_history(addr_unused)
            assert result is None, (
                f"verifier returned {result!r} on RPC failure; expected None "
                "so callers can fall back to the sync-only picker. Returning "
                "True would block deposits during a bitcoind outage; "
                "returning False would silently accept potentially-funded "
                "addresses"
            )
        finally:
            await broken_backend.close()
    finally:
        for wallet in (test_wallet, miner_wallet):
            try:
                await _rpc(cfg, "unloadwallet", [wallet])
            except Exception:
                pass
