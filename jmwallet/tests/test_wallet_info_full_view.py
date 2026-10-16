"""
Tests for the 'full' renderer of the extended wallet info view
(:mod:`jmwallet.cli.info_render`).

The renderer consumes the canonical row model (:mod:`jmwallet.wallet.rows`)
and only formats it: pipe-aligned tables, one line per UTXO (hard rule), no
elision, bare number cells with the units in the headers, exact confirmation
counts, explicit ``spend`` state,
and the red ``RU!`` marker at the end of the row for reused addresses.
"""

from __future__ import annotations

import pytest

from jmwallet.cli import info_render
from jmwallet.wallet.models import AddressInfo, UTXOInfo
from jmwallet.wallet.rows import (
    HiddenRow,
    build_branch_rows,
    summarize_branch,
    summarize_mixdepth,
)

NOW = 1_800_000_000
FB_EXPIRY = NOW + 30 * 86400  # fb locktime in the future


def _utxo(
    txid: str,
    vout: int,
    value: int,
    address: str,
    confs: int,
    *,
    path: str = "m/84'/1'/0'/0/0",
    frozen: bool = False,
    locktime: int | None = None,
) -> UTXOInfo:
    return UTXOInfo(
        txid=txid,
        vout=vout,
        value=value,
        address=address,
        confirmations=confs,
        scriptpubkey="0014" + "00" * 20,
        path=path,
        mixdepth=0,
        frozen=frozen,
        locktime=locktime,
    )


def _addr(
    address: str,
    index: int,
    *,
    balance: int = 0,
    status: str = "new",
    is_external: bool = True,
    utxos: list[UTXOInfo] | None = None,
    base_status: str | None = None,
    is_bond: bool = False,
    locktime: int | None = None,
    label: str = "",
) -> AddressInfo:
    return AddressInfo(
        address=address,
        index=index,
        balance=balance,
        status=status,  # type: ignore[arg-type]
        path=f"m/84'/1'/0'/{0 if is_external else 1}/{index}",
        is_external=is_external,
        is_bond=is_bond,
        locktime=locktime,
        utxos=utxos or [],
        label=label,
        base_status=base_status,  # type: ignore[arg-type]
    )


class TestBranchTable:
    def test_snapshot_regular_branch(self) -> None:
        """Pipe-aligned table: exact confs, explicit spendable state, RU!."""
        ext = [
            _addr("bc1qnew0", 0),
            _addr(
                "bc1qdep0",
                1,
                balance=109_812,
                status="deposit",
                utxos=[
                    _utxo("aa" * 32, 0, 9_812, "bc1qdep0", 26),
                    _utxo("bb" * 32, 1, 100_000, "bc1qdep0", 3, frozen=True),
                ],
            ),
            _addr(
                "bc1qru00",
                2,
                balance=50_000,
                status="reused",
                base_status="cj-out",
                utxos=[_utxo("cc" * 32, 0, 50_000, "bc1qru00", 7)],
            ),
            _addr("bc1qres0", 3, status="reserved", label="donation"),
        ]
        rows = build_branch_rows(ext, mixdepth=0, branch=0, now=NOW)
        lines = info_render.render_branch_table(rows)

        assert lines[0].startswith("idx") and "outpoint" in lines[0]
        # units live in the headers, the cells carry bare numbers
        assert "| sats " in lines[0] and "| confs " in lines[0]
        assert lines[1].count("-+-") == 6  # separator under every column
        # one line per UTXO (hard rule) + the two funded-address rows and
        # the empty new/reserved rows
        assert len(lines) == 2 + 5
        data_lines = lines[2:]
        # the first column is the /-prefixed derivation index (the branch
        # path is printed once above the table)
        assert [line.split("|")[0].strip() for line in data_lines] == [
            "/0",
            "/1",
            "/1",
            "/2",
            "/3",
        ]
        # bare amounts (sats unit in the header)
        assert [line.split("|")[2].strip() for line in data_lines] == [
            "0",
            "9,812",
            "100,000",
            "50,000",
            "0",
        ]
        # exact confirmation counts as bare cells, never ">= N"
        assert [line.split("|")[3].strip() for line in data_lines] == ["", "26", "3", "7", ""]
        assert all("conf" not in line and " sats" not in line for line in data_lines)
        assert not any(">= " in line for line in lines)
        # spendable shown explicitly (positive signal)
        assert sum("spend" in line for line in lines) == 2
        assert any("frozn" in line for line in lines)
        # RU! at the end of the row (after the outpoint), rsvd label in quotes
        assert any("cj-o" in line and line.endswith("RU!") for line in lines)
        assert any('rsvd "donation"' in line for line in lines)
        # pipe-aligned: every data row has the same column boundaries
        data_lines = lines[2:]
        assert len({line.index("|") for line in data_lines if "|" in line}) == 1
        # closed grid: every data row spans all columns (6 separators), even
        # rows whose trailing cells (state, outpoint) are empty
        assert all(line.count("|") == 6 for line in data_lines)

    def test_snapshot_fidelity_bond_branch(self) -> None:
        """The bond branch adds lock/redeem state + fb-date, retaining exact confs."""
        bonds = [
            _addr(
                "bc1pbond0",
                0,
                balance=60_000,
                status="bond",
                is_external=False,
                is_bond=True,
                locktime=FB_EXPIRY,
                utxos=[_utxo("dd" * 32, 0, 60_000, "bc1pbond0", 100, locktime=FB_EXPIRY)],
            ),
            _addr(
                "bc1pbond2",
                2,
                balance=0,
                status="bond",
                is_external=False,
                is_bond=True,
                locktime=NOW - 172_800,
            ),
        ]
        rows = build_branch_rows(bonds, mixdepth=0, branch=2, now=NOW)
        lines = info_render.render_branch_table(rows, fidelity_bond=True)

        assert "fb-date" in lines[0]
        assert any("fb-a" in line for line in lines)
        assert any("fb-x" in line for line in lines)
        # redeemed bond (no funds) stays visible with its locktime date
        assert any("bc1pbond2" in line for line in lines)
        # the state column carries the lock status (8 columns)
        assert "state" in lines[0]
        data_lines = lines[2:]
        assert all(line.count("|") == 7 for line in data_lines)
        assert [line.split("|")[3].strip() for line in data_lines] == ["100", ""]
        # /-prefixed derivation index — no locktime epoch glued to a path cell
        assert [line.split("|")[0].strip() for line in data_lines] == ["/0", "/2"]
        # lock status per row: a funded active bond locks; an empty bond has
        # no state (nothing to lock or redeem)
        assert [line.split("|")[5].strip() for line in data_lines] == ["lock", ""]

    @pytest.mark.parametrize("locked", [True, False])
    @pytest.mark.parametrize("pending", [True, False])
    @pytest.mark.parametrize("frozen", [True, False])
    def test_bond_state_preserves_frozen_flag(
        self, locked: bool, pending: bool, frozen: bool
    ) -> None:
        locktime = FB_EXPIRY if locked else NOW - 86_400
        addr = _addr(
            "tb1qbond",
            0,
            balance=5_000,
            status="bond",
            is_external=False,
            is_bond=True,
            locktime=locktime,
            utxos=[
                _utxo("ee" * 32, 0, 5_000, "tb1qbond", 12_345, frozen=frozen, locktime=locktime)
            ],
        )
        rows = build_branch_rows(
            [addr],
            mixdepth=0,
            branch=2,
            now=NOW,
            pending_addresses={addr.address} if pending else set(),
        )
        line = info_render.render_branch_table(rows, fidelity_bond=True)[2]
        state = "pend" if pending else "lock" if locked else "redeem"
        assert line.split("|")[5].strip() == (f"{state} frozn" if frozen else state)
        assert line.split("|")[3].strip() == "12,345"

    def test_hidden_note_mentions_show_empty(self) -> None:
        hidden = HiddenRow(mixdepth=0, branch=0, hidden_count=2)
        lines = info_render.render_branch_table([hidden])
        assert lines == ["(2 empty addresses hidden; pass --show-empty to display)"]

    def test_unconfirmed_state_for_0conf_utxo(self) -> None:
        addr = _addr(
            "bc1qdep0",
            0,
            balance=5_000,
            status="deposit",
            utxos=[_utxo("ee" * 32, 0, 5_000, "bc1qdep0", 0)],
        )
        rows = build_branch_rows([addr], mixdepth=0, branch=0, now=NOW)
        lines = info_render.render_branch_table(rows)
        assert any(line.split("|")[3].strip() == "0" and "unconf" in line for line in lines[2:])
        assert not any("spend" in line for line in lines[2:])

    def test_confs_thousands_separator(self) -> None:
        """Confirmation counts keep the thousands separator (unit in the header)."""
        addr = _addr(
            "bc1qdep0",
            0,
            balance=5_000,
            status="deposit",
            utxos=[_utxo("ee" * 32, 0, 5_000, "bc1qdep0", 12_345)],
        )
        rows = build_branch_rows([addr], mixdepth=0, branch=0, now=NOW)
        lines = info_render.render_branch_table(rows)
        assert any(line.split("|")[3].strip() == "12,345" for line in lines[2:])

    def test_global_num_width_aligns_amounts(self) -> None:
        """A caller-provided num_width right-aligns every amount cell."""
        rows = build_branch_rows([_addr("bc1qnew0", 0)], mixdepth=0, branch=0, now=NOW)
        lines = info_render.render_branch_table(rows, num_width=7)
        assert any("|       0 |" in line for line in lines[2:])

    def test_headers_regular_and_fidelity_bond(self) -> None:
        """Column order: the ``tag`` cell sits between ``confs`` and ``state``;
        the bond branch inserts ``fb-date`` after ``state`` (8 columns)."""
        rows = build_branch_rows([_addr("bc1qnew0", 0)], mixdepth=0, branch=0, now=NOW)
        header = info_render.render_branch_table(rows)[0]
        assert [cell.strip() for cell in header.split("|")] == [
            "idx",
            "address",
            "sats",
            "confs",
            "tag",
            "state",
            "outpoint",
        ]

        bond_rows = build_branch_rows(
            [
                _addr(
                    "bc1pbond0",
                    0,
                    balance=60_000,
                    status="bond",
                    is_external=False,
                    is_bond=True,
                    locktime=FB_EXPIRY,
                    utxos=[_utxo("dd" * 32, 0, 60_000, "bc1pbond0", 100, locktime=FB_EXPIRY)],
                )
            ],
            mixdepth=0,
            branch=2,
            now=NOW,
        )
        fb_header = info_render.render_branch_table(bond_rows, fidelity_bond=True)[0]
        assert [cell.strip() for cell in fb_header.split("|")] == [
            "idx",
            "address",
            "sats",
            "confs",
            "tag",
            "state",
            "fb-date",
            "outpoint",
        ]

    def test_separator_right_extended_to_sep_width(self) -> None:
        """``sep_width`` right-extends the dashed separator so every dashed
        line on the page shares one length; shorter values are a no-op."""
        rows = build_branch_rows([_addr("bc1qnew0", 0)], mixdepth=0, branch=0, now=NOW)
        natural = info_render.render_branch_table(rows)[1]
        assert len(natural) == info_render.separator_width(info_render.compute_widths(rows))

        target = len(natural) + 10
        assert info_render.render_branch_table(rows, sep_width=target)[1] == natural + "-" * 10
        assert info_render.render_branch_table(rows, sep_width=len(natural) - 5)[1] == natural


class TestRuMarkerColor:
    def test_red_on_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("jmwallet.cli.ansi.color_enabled", lambda: True)
        addr = _addr(
            "bc1qru00",
            0,
            balance=1_000,
            status="reused",
            base_status="deposit",
            utxos=[_utxo("ff" * 32, 0, 1_000, "bc1qru00", 5)],
        )
        rows = build_branch_rows([addr], mixdepth=0, branch=0, now=NOW)
        out = "\n".join(info_render.render_branch_table(rows))
        assert "\033[1;31mRU!\033[0m" in out
        # alignment is computed on the plain text, so columns still line up
        data_lines = out.splitlines()[2:]
        assert len(data_lines) == 1
        assert data_lines[0].count("|") == 6
        # appended at the very end of the row, right after the outpoint
        assert data_lines[0].endswith("\033[1;31mRU!\033[0m")
        assert f"{'ff' * 32}:0 \033[1;31mRU!\033[0m" in data_lines[0]

    def test_plain_off_tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("jmwallet.cli.ansi.color_enabled", lambda: False)
        addr = _addr(
            "bc1qru00",
            0,
            balance=1_000,
            status="reused",
            base_status="deposit",
            utxos=[_utxo("ff" * 32, 0, 1_000, "bc1qru00", 5)],
        )
        rows = build_branch_rows([addr], mixdepth=0, branch=0, now=NOW)
        out = "\n".join(info_render.render_branch_table(rows))
        assert "RU!" in out
        assert "\033[" not in out
        # appended at the very end of the row, right after the outpoint
        line = out.splitlines()[2]
        assert line.endswith("RU!")
        assert f"{'ff' * 32}:0 RU!" in line


class TestSummaryLines:
    def test_branch_summary_spendable(self) -> None:
        rows = build_branch_rows(
            [
                _addr(
                    "bc1qdep0",
                    0,
                    balance=10_000,
                    status="deposit",
                    utxos=[
                        _utxo("aa" * 32, 0, 7_000, "bc1qdep0", 5),
                        _utxo("bb" * 32, 1, 3_000, "bc1qdep0", 5, frozen=True),
                    ],
                )
            ],
            mixdepth=0,
            branch=0,
            now=NOW,
        )
        summary = summarize_branch(rows, mixdepth=0, branch=0, now=NOW)
        line = info_render.render_branch_summary(summary)
        assert line == "Balance: 10,000 sats (spendable: 7,000 sats)"

    def test_bond_branch_summary_locked_and_expired(self) -> None:
        rows = build_branch_rows(
            [
                _addr(
                    "bc1pbond0",
                    0,
                    balance=60_000,
                    status="bond",
                    is_external=False,
                    is_bond=True,
                    locktime=FB_EXPIRY,
                    utxos=[_utxo("dd" * 32, 0, 60_000, "bc1pbond0", 100, locktime=FB_EXPIRY)],
                ),
                _addr(
                    "bc1pbond1",
                    1,
                    balance=40_000,
                    status="bond",
                    is_external=False,
                    is_bond=True,
                    locktime=NOW - 86_400,
                    utxos=[_utxo("ee" * 32, 0, 40_000, "bc1pbond1", 100, locktime=NOW - 86_400)],
                ),
            ],
            mixdepth=0,
            branch=2,
            now=NOW,
        )
        summary = summarize_branch(rows, mixdepth=0, branch=2, now=NOW)
        line = info_render.render_branch_summary(summary)
        assert line == (
            "Balance: 100,000 sats (60,000 time-locked + 40,000 expired; redeemable: 40,000 sats)"
        )

    def test_bond_branch_summary_locked_only(self) -> None:
        """All funds time-locked: nothing redeemable yet."""
        rows = build_branch_rows(
            [
                _addr(
                    "bc1pbond0",
                    0,
                    balance=60_000,
                    status="bond",
                    is_external=False,
                    is_bond=True,
                    locktime=FB_EXPIRY,
                    utxos=[_utxo("dd" * 32, 0, 60_000, "bc1pbond0", 100, locktime=FB_EXPIRY)],
                )
            ],
            mixdepth=0,
            branch=2,
            now=NOW,
        )
        summary = summarize_branch(rows, mixdepth=0, branch=2, now=NOW)
        line = info_render.render_branch_summary(summary)
        assert line == "Balance: 60,000 sats (60,000 time-locked; redeemable: 0 sats)"

    def test_bond_branch_summary_expired_only(self) -> None:
        """All funds expired: the full balance is redeemable."""
        rows = build_branch_rows(
            [
                _addr(
                    "bc1pbond1",
                    1,
                    balance=40_000,
                    status="bond",
                    is_external=False,
                    is_bond=True,
                    locktime=NOW - 86_400,
                    utxos=[_utxo("ee" * 32, 0, 40_000, "bc1pbond1", 100, locktime=NOW - 86_400)],
                )
            ],
            mixdepth=0,
            branch=2,
            now=NOW,
        )
        summary = summarize_branch(rows, mixdepth=0, branch=2, now=NOW)
        line = info_render.render_branch_summary(summary)
        assert line == "Balance: 40,000 sats (40,000 expired; redeemable: 40,000 sats)"

    def test_mixdepth_summary_totals(self) -> None:
        ext = summarize_branch(
            build_branch_rows(
                [
                    _addr(
                        "bc1qdep0",
                        0,
                        balance=10_000,
                        status="deposit",
                        utxos=[_utxo("aa" * 32, 0, 10_000, "bc1qdep0", 5)],
                    )
                ],
                mixdepth=0,
                branch=0,
                now=NOW,
            ),
            mixdepth=0,
            branch=0,
            now=NOW,
        )
        internal = summarize_branch(
            build_branch_rows(
                [
                    _addr(
                        "bc1qchg0",
                        0,
                        balance=5_000,
                        status="cj-change",
                        is_external=False,
                        utxos=[_utxo("bb" * 32, 0, 5_000, "bc1qchg0", 5)],
                    )
                ],
                mixdepth=0,
                branch=1,
                now=NOW,
            ),
            mixdepth=0,
            branch=1,
            now=NOW,
        )
        line = info_render.render_mixdepth_summary(summarize_mixdepth([ext, internal], mixdepth=0))
        assert line.endswith("15,000 sats (spendable: 15,000 sats)")
        assert "Balance for mixdepth 0:" in line


class TestLegend:
    def test_legend_covers_vocabulary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("jmwallet.cli.ansi.color_enabled", lambda: False)
        text = "\n".join(info_render.render_legend())
        for label in (
            "new",
            "dep",
            "cj-o",
            "cj-c",
            "chg",
            "used",
            "flag",
            "rsvd",
            "fb-a",
            "fb-x",
        ):
            assert label in text
        for state in ("spend", "frozn", "pend", "unconf", "lock", "redeem"):
            assert state in text
        assert "RU!" in text
        assert "\033[" not in text

    def test_legend_hides_bond_vocabulary_when_hidden(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``show_fidelity_bonds=False`` drops the fb-a/fb-x tags and the
        lock/redeem states (hidden bond branch); the rest of the vocabulary
        stays."""
        monkeypatch.setattr("jmwallet.cli.ansi.color_enabled", lambda: False)
        text = "\n".join(info_render.render_legend(show_fidelity_bonds=False))
        for gone in ("fb-a", "fb-x", "lock", "redeem", "fb-date"):
            assert gone not in text
        for kept in (
            "new",
            "dep",
            "cj-o",
            "cj-c",
            "chg",
            "used",
            "flag",
            "rsvd",
            "spend",
            "frozn",
            "pend",
            "unconf",
            "RU!",
        ):
            assert kept in text
