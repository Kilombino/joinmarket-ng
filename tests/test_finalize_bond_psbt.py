"""Tests for the standalone signed bond PSBT finalizer."""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from finalize_bond_psbt import (
    _encode_varint,
    _extract_freeze_script_pubkey,
    _parse_der_signature,
    _read_psbt_pair,
    _read_varint,
    finalize_bond_psbt,
    parse_signed_bond_psbt,
    verify_bond_signature,
)

SIGNED_SPECTER_PSBT_B64 = (
    "cHNidP8BAFICAAAAATE7hixB8V/y7oXB1Ckyveg+WIPrW0RlxtFNPdv3o6BUAQAAAAD+////"
    "AdBBDwAAAAAAFgAUr8yGDmmY3JWBeIXYdqhZO4fpB4MAuVVpAAEBK0BCDwAAAAAAIgAg6WSb"
    "rbiM8Zvs3u3QwM5l56zhJdTDwpQnSzvGG3PlqeEiAgIJ014SVJgJ37nyNaD9IVJ7d042rAku"
    "z0/0N22Q2dWMBEcwRAIgWYcBBSQzdRvnuXhSFzSa+oczdHEGFS2Vbe3e+YHrNrQCIFe8omA0"
    "wStZo2SmHImP0gzc/zVrqM0zUSDns6rY04klAQEDBAEAAAABBSoEALlVabF1IQIJ014SVJgJ"
    "37nyNaD9IVJ7d042rAkuz0/0N22Q2dWMBKwAAA=="
)

WITNESS_SCRIPT_HEX = (
    "0400b95569b175210209d35e12549809dfb9f235a0fd21527b774e36ac092ecf4ff4376"
    "d90d9d58c04ac"
)

# Hardware wallet compatibility test vector from docs/fidelity-bond-operations.md:
# the public BIP39 test mnemonic ("abandon" x11 + "about"), key at
# m/84'/0'/0'/0/0, bond locktime 2026-02-01 UTC, synthetic UTXO. Signed with
# scripts/sign_bond_mnemonic.py (deterministic RFC 6979 signature).
SIGNED_ABANDON_PSBT_B64 = (
    "cHNidP8BAFICAAAAARERERERERERERERERERERERERERERERERERERERERERAAAAAAD+////"
    "ATCGAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOKAl35pAAEBK6CGAQAAAAAAIgAgG15M"
    "3/mFQhRrS/nVEhPu1StoJSuBCk8VquAtQsl/BK4BAwQBAAAAAQUqBICXfmmxdSEDMNVP0N1C"
    "Cm5fjTYk9fNILK41D3nV8HU79b7vnC2RrzysIgYDMNVP0N1CCm5fjTYk9fNILK41D3nV8HU7"
    "9b7vnC2RrzwYc8XaClQAAIAAAACAAAAAgAAAAAAAAAAAIgIDMNVP0N1CCm5fjTYk9fNILK41"
    "D3nV8HU79b7vnC2RrzxHMEQCIHmpkCNo23vbADv4KgzswRhHoky8pkmGUUwkxWVtXhRBAiBC"
    "XkrgsSxJ2pX95etCNBaceyG2TIjKUO5KE8fFvNfkRwEAAA=="
)

ABANDON_FINAL_TX_HEX = (
    "020000000001011111111111111111111111111111111111111111111111111111111111"
    "1111110000000000feffffff013086010000000000160014c0cebcd6c3d3ca8c75dc5ec6"
    "2ebe55330ef910e202473044022079a9902368db7bdb003bf82a0cecc11847a24cbca649"
    "86514c24c5656d5e14410220425e4ae0b12c49da95fde5eb4234169c7b21b64c88ca50ee"
    "4a13c7c5bcd7e447012a0480977e69b175210330d54fd0dd420a6e5f8d3624f5f3482cae"
    "350f79d5f0753bf5beef9c2d91af3cac80977e69"
)

# secp256k1 group order (for building the high-S test signature)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _remove_partial_signature(psbt_b64: str) -> str:
    raw = base64.b64decode(psbt_b64)
    pos = 5

    # Copy global map through separator.
    while True:
        key, _, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            break

    output = bytearray(raw[:pos])

    # Copy input map, skipping partial signature pairs.
    while True:
        pair_start = pos
        key, _, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            output.append(0)
            break
        if key[0] != 0x02:
            output.extend(raw[pair_start:next_pos])

    output.extend(raw[pos:])
    return base64.b64encode(output).decode()


def _replace_partial_signature_pubkey(psbt_b64: str, pubkey: bytes) -> str:
    raw = base64.b64decode(psbt_b64)
    pos = 5

    while True:
        key, _, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            break

    output = bytearray(raw[:pos])

    while True:
        pair_start = pos
        key, value, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            output.append(0)
            break
        if key[0] == 0x02:
            assert value is not None
            new_key = b"\x02" + pubkey
            output.extend(_encode_varint(len(new_key)) + new_key)
            output.extend(_encode_varint(len(value)) + value)
        else:
            output.extend(raw[pair_start:next_pos])

    output.extend(raw[pos:])
    return base64.b64encode(output).decode()


def _replace_partial_signature_value(psbt_b64: str, signature: bytes) -> str:
    raw = base64.b64decode(psbt_b64)
    pos = 5

    while True:
        key, _, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            break

    output = bytearray(raw[:pos])

    while True:
        pair_start = pos
        key, value, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            output.append(0)
            break
        if key[0] == 0x02:
            output.extend(_encode_varint(len(key)) + key)
            output.extend(_encode_varint(len(signature)) + signature)
        else:
            output.extend(raw[pair_start:next_pos])

    output.extend(raw[pos:])
    return base64.b64encode(output).decode()


def _der_int(value: int) -> bytes:
    encoded = value.to_bytes(max((value.bit_length() + 7) // 8, 1), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + bytes([len(encoded)]) + encoded


def _der_encode(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _remove_first_separator(psbt_b64: str) -> str:
    raw = base64.b64decode(psbt_b64)
    pos = 5

    while True:
        key, _, next_pos = _read_psbt_pair(raw, pos)
        pos = next_pos
        if key is None:
            return base64.b64encode(raw[: pos - 1]).decode()


class TestParseSignedBondPSBT:
    def test_extracts_signed_bond_fields(self) -> None:
        result = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)

        assert result.witness_script.hex() == WITNESS_SCRIPT_HEX
        assert result.signature[-1] == 0x01
        assert result.unsigned_tx.hex().startswith("02000000")
        assert result.utxo_value == 1_000_000
        assert result.pubkey.hex() == (
            "0209d35e12549809dfb9f235a0fd21527b774e36ac092ecf4ff4376d90d9d58c04"
        )

    def test_unsigned_psbt_raises(self) -> None:
        with pytest.raises(ValueError, match="partial signature"):
            parse_signed_bond_psbt(_remove_partial_signature(SIGNED_SPECTER_PSBT_B64))

    def test_witness_script_mismatch_raises(self) -> None:
        raw = bytearray(base64.b64decode(SIGNED_SPECTER_PSBT_B64))
        needle = hashlib.sha256(bytes.fromhex(WITNESS_SCRIPT_HEX)).digest()
        offset = bytes(raw).index(needle)
        raw[offset] ^= 0x01

        with pytest.raises(ValueError, match="does not match"):
            parse_signed_bond_psbt(base64.b64encode(raw).decode())

    def test_partial_signature_pubkey_mismatch_raises(self) -> None:
        wrong_pubkey = bytes.fromhex("03" + "11" * 32)
        psbt = _replace_partial_signature_pubkey(SIGNED_SPECTER_PSBT_B64, wrong_pubkey)

        with pytest.raises(ValueError, match="pubkey does not match"):
            parse_signed_bond_psbt(psbt)

    def test_truncated_psbt_raises_value_error(self) -> None:
        raw = base64.b64decode(SIGNED_SPECTER_PSBT_B64)
        truncated = base64.b64encode(raw[:-7]).decode()

        with pytest.raises(ValueError, match="truncated|Truncated|Unexpected end"):
            parse_signed_bond_psbt(truncated)

    def test_missing_global_separator_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="global map is truncated"):
            parse_signed_bond_psbt(_remove_first_separator(SIGNED_SPECTER_PSBT_B64))

    def test_truncated_witness_script_raises_value_error(self) -> None:
        truncated_script = bytes.fromhex(WITNESS_SCRIPT_HEX)[:7]

        with pytest.raises(ValueError, match="truncated|missing"):
            _extract_freeze_script_pubkey(truncated_script)

    def test_line_wrapped_psbt_is_accepted(self) -> None:
        wrapped = "\n".join(
            SIGNED_SPECTER_PSBT_B64[i : i + 64]
            for i in range(0, len(SIGNED_SPECTER_PSBT_B64), 64)
        )

        assert (
            parse_signed_bond_psbt(wrapped).witness_script.hex() == WITNESS_SCRIPT_HEX
        )


class TestFinalizeBondPSBT:
    def test_finalize_outputs_witness_transaction(self) -> None:
        signed_hex = finalize_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        signed = bytes.fromhex(signed_hex)

        assert signed[4] == 0x00
        assert signed[5] == 0x01

        offset = 6
        input_count, offset = _read_varint(signed, offset)
        assert input_count == 1
        offset += 32 + 4
        script_len, offset = _read_varint(signed, offset)
        offset += script_len + 4

        output_count, offset = _read_varint(signed, offset)
        assert output_count == 1
        offset += 8
        output_script_len, offset = _read_varint(signed, offset)
        offset += output_script_len

        witness_items, offset = _read_varint(signed, offset)
        assert witness_items == 2

        sig_len, offset = _read_varint(signed, offset)
        signature = signed[offset : offset + sig_len]
        offset += sig_len
        assert signature[-1] == 0x01

        script_len, offset = _read_varint(signed, offset)
        witness_script = signed[offset : offset + script_len]
        assert witness_script.hex() == WITNESS_SCRIPT_HEX

    def test_finalized_tx_has_expected_hex(self) -> None:
        assert finalize_bond_psbt(SIGNED_SPECTER_PSBT_B64) == (
            "02000000000101313b862c41f15ff2ee85c1d42932bde83e5883eb5b4465c6d14d3d"
            "dbf7a3a0540100000000feffffff01d0410f0000000000160014afcc860e6998dc95"
            "817885d876a8593b87e90783024730440220598701052433751be7b9785217349afa"
            "8733747106152d956deddef981eb36b4022057bca26034c12b59a364a61c898fd20"
            "cdcff356ba8cd335120e7b3aad8d38925012a0400b95569b175210209d35e125498"
            "09dfb9f235a0fd21527b774e36ac092ecf4ff4376d90d9d58c04ac00b95569"
        )


class TestSignatureVerification:
    """Cryptographic verification of the partial signature (BIP143)."""

    def test_specter_device_signature_verifies(self) -> None:
        """The real Specter DIY signature must pass verification."""
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        verify_bond_signature(
            tx=parsed.tx_fields,
            witness_script=parsed.witness_script,
            utxo_value=parsed.utxo_value,
            pubkey=parsed.pubkey,
            signature=parsed.signature,
        )

    def test_wrong_signature_rejected(self) -> None:
        """A well-formed DER signature for a different tx must be rejected."""
        # Valid DER signature taken from the abandon-mnemonic vector, which
        # signs a different transaction with a different key.
        wrong_sig = bytes.fromhex(
            "3044022079a9902368db7bdb003bf82a0cecc11847a24cbca64986514c24c565"
            "6d5e14410220425e4ae0b12c49da95fde5eb4234169c7b21b64c88ca50ee4a13"
            "c7c5bcd7e44701"
        )
        psbt = _replace_partial_signature_value(SIGNED_SPECTER_PSBT_B64, wrong_sig)

        with pytest.raises(ValueError, match="[Ss]ignature verification failed"):
            finalize_bond_psbt(psbt)

    def test_garbage_signature_rejected(self) -> None:
        """A non-DER signature blob must be rejected."""
        psbt = _replace_partial_signature_value(
            SIGNED_SPECTER_PSBT_B64, b"\xde\xad\xbe\xef" * 10 + b"\x01"
        )

        with pytest.raises(ValueError, match="DER"):
            finalize_bond_psbt(psbt)

    def test_high_s_signature_verifies_with_warning(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The (r, n - s) counterpart signature is valid but warns (non-standard)."""
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        r, s = _parse_der_signature(parsed.signature[:-1])
        high_s_sig = _der_encode(r, SECP256K1_N - s) + b"\x01"
        psbt = _replace_partial_signature_value(SIGNED_SPECTER_PSBT_B64, high_s_sig)

        signed_hex = finalize_bond_psbt(psbt)

        assert high_s_sig.hex() in signed_hex
        assert "high-S" in capsys.readouterr().err

    def test_der_parse_rejects_bad_markers(self) -> None:
        with pytest.raises(ValueError, match="DER"):
            _parse_der_signature(b"\x31" + b"\x00" * 10)
        with pytest.raises(ValueError, match="DER"):
            _parse_der_signature(b"\x30\x06\x03\x01\x01\x02\x01\x01")

    def test_der_parse_rejects_excessive_leading_zero(self) -> None:
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        der = parsed.signature[:-1]
        malformed = (
            b"\x30"
            + bytes([der[1] + 1])
            + b"\x02"
            + bytes([der[3] + 1])
            + b"\x00"
            + der[4:]
        )
        psbt = _replace_partial_signature_value(
            SIGNED_SPECTER_PSBT_B64, malformed + b"\x01"
        )

        with pytest.raises(ValueError, match="unnecessary leading zero"):
            finalize_bond_psbt(psbt)

    def test_der_parse_rejects_missing_required_leading_zero(self) -> None:
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        r, s = _parse_der_signature(parsed.signature[:-1])
        high_s_der = _der_encode(r, SECP256K1_N - s)
        r_len = high_s_der[3]
        s_len_pos = 5 + r_len
        s_pos = s_len_pos + 1
        assert high_s_der[s_pos] == 0
        assert high_s_der[s_pos + 1] & 0x80
        malformed = (
            b"\x30"
            + bytes([high_s_der[1] - 1])
            + high_s_der[2:s_len_pos]
            + bytes([high_s_der[s_len_pos] - 1])
            + high_s_der[s_pos + 1 :]
        )
        psbt = _replace_partial_signature_value(
            SIGNED_SPECTER_PSBT_B64, malformed + b"\x01"
        )

        with pytest.raises(ValueError, match="negative"):
            finalize_bond_psbt(psbt)

    @pytest.mark.parametrize(
        "der",
        [
            b"\x30\x06\x02\x00\x02\x02\x01\x01",
            b"\x30\x06\x02\x02\x01\x01\x02\x00",
        ],
    )
    def test_der_parse_rejects_zero_length_integers(self, der: bytes) -> None:
        with pytest.raises(ValueError, match="empty"):
            _parse_der_signature(der)

    def test_der_parse_rejects_trailing_bytes(self) -> None:
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        der = parsed.signature[:-1]
        malformed = b"\x30" + bytes([der[1] + 1]) + der[2:] + b"\x00"

        with pytest.raises(ValueError, match="trailing bytes"):
            _parse_der_signature(malformed)

    def test_der_parse_rejects_inexact_sequence_length(self) -> None:
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        der = parsed.signature[:-1]
        malformed = der[:1] + bytes([der[1] - 1]) + der[2:]

        with pytest.raises(ValueError, match="invalid DER length"):
            _parse_der_signature(malformed)

    def test_der_parse_accepts_valid_signature(self) -> None:
        parsed = parse_signed_bond_psbt(SIGNED_SPECTER_PSBT_B64)
        r, s = _parse_der_signature(parsed.signature[:-1])
        assert _der_encode(r, s) == parsed.signature[:-1]


class TestAbandonMnemonicVector:
    """The documented hardware wallet compatibility test vector.

    docs/fidelity-bond-operations.md publishes an unsigned test PSBT built from the
    public BIP39 test mnemonic so users can check whether their device model
    can sign fidelity bond spends before locking real funds. This signed
    counterpart (produced with scripts/sign_bond_mnemonic.py) must finalize
    and verify.
    """

    def test_parsed_fields(self) -> None:
        parsed = parse_signed_bond_psbt(SIGNED_ABANDON_PSBT_B64)

        assert parsed.utxo_value == 100_000
        # Locktime 2026-02-01 00:00 UTC and the BIP84 test vector pubkey.
        assert parsed.witness_script.hex() == (
            "0480977e69b175210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f075"
            "3bf5beef9c2d91af3cac"
        )
        assert parsed.pubkey.hex() == (
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
        )

    def test_finalizes_and_verifies_to_expected_hex(self) -> None:
        assert finalize_bond_psbt(SIGNED_ABANDON_PSBT_B64) == ABANDON_FINAL_TX_HEX
