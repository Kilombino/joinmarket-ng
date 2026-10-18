"""Unit tests for pre-flight UTXO eligibility classification (issue #528)."""

from __future__ import annotations

import time

from jmwallet.wallet.models import UTXOInfo

from taker.eligibility import (
    NO_ELIGIBLE_PREFIX,
    classify_utxos,
    fidelity_bond_inputs,
    podle_threshold_met,
    selectable_for_interactive,
)
from taker.podle import get_eligible_podle_utxos, select_podle_utxo

SPK = "0014" + "00" * 20


def _utxo(
    *,
    txid_char: str = "a",
    vout: int = 0,
    value: int = 25_000_000,
    confirmations: int = 10,
    frozen: bool = False,
    locktime: int | None = None,
    label: str | None = None,
) -> UTXOInfo:
    return UTXOInfo(
        txid=txid_char * 64,
        vout=vout,
        value=value,
        address="bcrt1qtest",
        confirmations=confirmations,
        scriptpubkey=SPK,
        path="m/84'/1'/0'/0/0",
        mixdepth=0,
        locktime=locktime,
        label=label,
        frozen=frozen,
    )


def test_classify_eligible_only() -> None:
    utxos = [_utxo(txid_char="a"), _utxo(txid_char="b", value=5_000_000)]
    breakdown = classify_utxos(utxos, mixdepth=0, min_confirmations=5)
    assert len(breakdown.eligible) == 2
    assert breakdown.eligible_value == 30_000_000
    assert breakdown.total == 2


def test_classify_immature() -> None:
    utxos = [_utxo(confirmations=2)]
    breakdown = classify_utxos(utxos, mixdepth=0, min_confirmations=5)
    assert breakdown.eligible == []
    assert len(breakdown.immature) == 1
    reason = breakdown.no_eligible_reason()
    assert reason.startswith(NO_ELIGIBLE_PREFIX)
    assert "below 5 confirmation(s)" in reason


def test_classify_frozen() -> None:
    breakdown = classify_utxos([_utxo(frozen=True)], mixdepth=0, min_confirmations=5)
    assert breakdown.eligible == []
    assert len(breakdown.frozen) == 1
    assert "1 frozen" in breakdown.no_eligible_reason()


def test_classify_locked_and_unlocked_bonds() -> None:
    future = int(time.time()) + 100_000
    past = int(time.time()) - 100_000
    breakdown = classify_utxos(
        [_utxo(txid_char="a", locktime=future), _utxo(txid_char="b", locktime=past)],
        mixdepth=0,
        min_confirmations=5,
    )
    assert breakdown.eligible == []
    assert len(breakdown.locked_bonds) == 1
    assert len(breakdown.unlocked_bonds) == 1
    reason = breakdown.no_eligible_reason()
    assert "time-locked fidelity bond" in reason
    assert "not auto-spent" in reason


def test_classify_reserved() -> None:
    u = _utxo(txid_char="a")
    breakdown = classify_utxos(
        [u], mixdepth=0, min_confirmations=5, reserved_outpoints={(u.txid, u.vout)}
    )
    assert breakdown.eligible == []
    assert len(breakdown.reserved) == 1
    assert "in-flight CoinJoin" in breakdown.no_eligible_reason()


def test_no_utxos_reason() -> None:
    breakdown = classify_utxos([], mixdepth=3, min_confirmations=5)
    assert breakdown.no_eligible_reason() == f"{NO_ELIGIBLE_PREFIX} 3 (no UTXOs present)"


def test_selectable_for_interactive_excludes_frozen_and_locked_bonds() -> None:
    future = int(time.time()) + 100_000
    utxos = [
        _utxo(txid_char="a"),  # selectable
        _utxo(txid_char="b", frozen=True),  # not selectable
        _utxo(txid_char="c", locktime=future),  # locked bond, not selectable
        _utxo(txid_char="d", confirmations=1),  # immature, not selectable
    ]
    selectable = selectable_for_interactive(utxos, min_confirmations=5)
    assert len(selectable) == 1
    assert selectable[0].txid == "a" * 64


def test_selectable_for_interactive_excludes_expired_bonds() -> None:
    """Expired bonds are redeemable by direct send only, never CoinJoin inputs."""
    past = int(time.time()) - 100_000
    regular = _utxo(txid_char="a")
    expired_bond = _utxo(txid_char="b", locktime=past)

    assert selectable_for_interactive([regular, expired_bond], min_confirmations=5) == [regular]
    assert selectable_for_interactive([expired_bond], min_confirmations=5) == []


def test_fidelity_bond_inputs_flags_locktime_and_p2wsh() -> None:
    past = int(time.time()) - 100_000
    future = int(time.time()) + 100_000
    regular = _utxo(txid_char="a")
    expired_bond = _utxo(txid_char="b", locktime=past)
    locked_bond = _utxo(txid_char="c", locktime=future)
    # A P2WSH output whose locktime was not populated must still be rejected,
    # matching the signer guard.
    p2wsh_without_locktime = _utxo(txid_char="d")
    p2wsh_without_locktime.scriptpubkey = "0020" + "dd" * 32

    flagged = fidelity_bond_inputs([regular, expired_bond, locked_bond, p2wsh_without_locktime])

    assert flagged == [expired_bond, locked_bond, p2wsh_without_locktime]
    assert fidelity_bond_inputs([regular]) == []


def test_podle_candidates_exclude_bonds_and_p2wsh() -> None:
    """A bond must never be the PoDLE UTXO revealed to makers in !auth."""
    past = int(time.time()) - 100_000
    regular = _utxo(txid_char="a", value=25_000_000)
    expired_bond = _utxo(txid_char="b", value=50_000_000, locktime=past)
    p2wsh = _utxo(txid_char="c", value=50_000_000)
    p2wsh.scriptpubkey = "0020" + "cc" * 32

    eligible = get_eligible_podle_utxos(
        [regular, expired_bond, p2wsh], cj_amount=10_000_000, min_confirmations=5
    )

    assert eligible == [regular]
    assert select_podle_utxo([expired_bond, p2wsh], cj_amount=10_000_000) is None


def test_selectable_for_interactive_excludes_in_flight_inputs() -> None:
    in_use = _utxo(txid_char="a")
    available = _utxo(txid_char="b")

    selectable = selectable_for_interactive(
        [in_use, available],
        min_confirmations=5,
        excluded_outpoints={(in_use.txid, in_use.vout)},
    )

    assert selectable == [available]


def test_podle_threshold_met() -> None:
    # 20% of 10_000_000 = 2_000_000
    eligible = [_utxo(value=2_000_000)]
    assert podle_threshold_met(eligible, 10_000_000, 5, 20) is True
    assert podle_threshold_met([_utxo(value=1_999_999)], 10_000_000, 5, 20) is False


def test_podle_threshold_respects_confirmations() -> None:
    eligible = [_utxo(value=10_000_000, confirmations=2)]
    assert podle_threshold_met(eligible, 10_000_000, 5, 20) is False
