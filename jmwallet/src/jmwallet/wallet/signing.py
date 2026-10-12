"""
Bitcoin transaction signing utilities for P2WPKH and P2WSH inputs.

BIP-143 sighash computation delegates to ``python-bitcointx``'s
``SignatureHash`` so consensus-critical preimage construction lives in
an audited library. The transaction is serialized via the in-tree
``ParsedTransaction`` and handed to bitcointx's ``CTransaction``.
"""

from __future__ import annotations

from typing import cast

from bitcointx.core import CMutableTransaction, CTransaction
from bitcointx.core.key import CKey
from bitcointx.core.script import SIGVERSION_WITNESS_V0, CScript, SIGHASH_Type, SignatureHash
from jmcore.bitcoin import (
    ParsedTransaction,
    TxInput,
    TxOutput,
    create_p2wpkh_script_code,
    decode_varint,
    encode_varint,
    hash256,
    parse_transaction_bytes,
    serialize_transaction,
)
from jmcore.crypto import verify_strict_ecdsa

# Backward-compat alias: old code imports ``Transaction`` from here.
Transaction = ParsedTransaction

# Alias for backward compatibility
read_varint = decode_varint


class TransactionSigningError(Exception):
    pass


def deserialize_transaction(tx_bytes: bytes) -> ParsedTransaction:
    """Deserialize a raw transaction for signing.

    Delegates to :func:`jmcore.bitcoin.parse_transaction_bytes` which now
    returns typed ``TxInput`` / ``TxOutput`` objects with the dual-accessor
    API required by the signing code.

    Raises:
        TransactionSigningError: If the transaction bytes cannot be parsed.
    """
    try:
        return parse_transaction_bytes(tx_bytes)
    except Exception as e:
        raise TransactionSigningError(f"Failed to parse transaction: {e}") from e


def compute_sighash_segwit(
    tx: ParsedTransaction,
    input_index: int,
    script_code: bytes,
    value: int,
    sighash_type: int,
) -> bytes:
    """Compute the BIP-143 sighash for a segwit input.

    Delegates to :func:`bitcointx.core.script.SignatureHash` with
    ``SIGVERSION_WITNESS_V0``. The ``ParsedTransaction`` is re-serialized
    and parsed by bitcointx so we never re-implement the BIP-143 preimage
    layout in-tree.
    """
    try:
        if input_index >= len(tx.inputs):
            raise TransactionSigningError("Input index out of range")

        ctx = CTransaction.deserialize(
            serialize_transaction(tx.version, tx.inputs, tx.outputs, tx.locktime)
        )
        if ctx.nLockTime > 0x7FFFFFFF:
            # bitcointx packs nLockTime into the BIP-143 preimage as a signed
            # int32; its two's complement gives the same four bytes.
            mutable = CMutableTransaction.from_tx(ctx)
            mutable.nLockTime -= 1 << 32
            ctx = mutable
        return bytes(
            SignatureHash(
                CScript(script_code),
                ctx,
                input_index,
                SIGHASH_Type(sighash_type),
                amount=value,
                sigversion=SIGVERSION_WITNESS_V0,
            )
        )

    except TransactionSigningError:
        raise
    except Exception as e:
        raise TransactionSigningError(f"Failed to compute sighash: {e}") from e


def sign_p2wpkh_input(
    tx: ParsedTransaction,
    input_index: int,
    script_code: bytes,
    value: int,
    private_key: CKey,
    sighash_type: int = 1,
) -> bytes:
    """Sign a P2WPKH input.

    Args:
        tx: The transaction to sign
        input_index: Index of the input to sign
        script_code: The scriptCode for signing (P2PKH script for P2WPKH)
        value: The value of the input being spent (in satoshis)
        private_key: Signing private key
        sighash_type: Sighash type (default SIGHASH_ALL = 1)

    Returns:
        DER-encoded signature with sighash type byte appended
    """
    if sighash_type != 1:
        raise TransactionSigningError(
            f"Unsupported sighash type {sighash_type}; only SIGHASH_ALL (0x01) allowed for signing"
        )

    sighash = compute_sighash_segwit(tx, input_index, script_code, value, sighash_type)

    # Sign the pre-hashed sighash (it is already SHA256d).
    signature = cast(bytes, private_key.sign(sighash, _ecdsa_sig_grind_low_r=False))

    return signature + bytes([sighash_type])


def verify_p2wpkh_signature(
    tx: ParsedTransaction,
    input_index: int,
    script_code: bytes,
    value: int,
    signature: bytes,
    pubkey: bytes,
) -> bool:
    """Verify a P2WPKH signature.

    Args:
        tx: The transaction containing the input
        input_index: Index of the input to verify
        script_code: The scriptCode (P2PKH script for P2WPKH)
        value: The value of the input being spent (in satoshis)
        signature: DER-encoded signature with sighash type byte appended
        pubkey: Public key bytes (compressed or uncompressed)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Extract sighash type from last byte of signature
        if not signature:
            return False
        sighash_type = signature[-1]
        der_signature = signature[:-1]

        sighash = compute_sighash_segwit(tx, input_index, script_code, value, sighash_type)

        return verify_strict_ecdsa(sighash, der_signature, pubkey)
    except Exception:
        return False


def create_witness_stack(signature: bytes, pubkey_bytes: bytes) -> list[bytes]:
    return [signature, pubkey_bytes]


def sign_p2wsh_input(
    tx: ParsedTransaction,
    input_index: int,
    witness_script: bytes,
    value: int,
    private_key: CKey,
    sighash_type: int = 1,
) -> bytes:
    """Sign a P2WSH input.

    For P2WSH, the scriptCode in BIP143 signing is the witness script itself.

    Args:
        tx: The transaction to sign
        input_index: Index of the input to sign
        witness_script: The witness script (e.g., timelocked freeze script)
        value: The value of the input being spent (in satoshis)
        private_key: Signing private key
        sighash_type: Sighash type (default SIGHASH_ALL = 1)

    Returns:
        DER-encoded signature with sighash type byte appended
    """
    if sighash_type != 1:
        raise TransactionSigningError(
            f"Unsupported sighash type {sighash_type}; only SIGHASH_ALL (0x01) allowed for signing"
        )

    # For P2WSH, the scriptCode is the witness script itself
    sighash = compute_sighash_segwit(tx, input_index, witness_script, value, sighash_type)

    # Sign the pre-hashed sighash (it is already SHA256d).
    signature = cast(bytes, private_key.sign(sighash, _ecdsa_sig_grind_low_r=False))

    return signature + bytes([sighash_type])


def verify_p2wsh_signature(
    tx: ParsedTransaction,
    input_index: int,
    witness_script: bytes,
    value: int,
    signature: bytes,
    pubkey: bytes,
) -> bool:
    """Verify a P2WSH BIP143 signature against its witness script."""
    try:
        if not signature:
            return False
        sighash_type = signature[-1]
        sighash = compute_sighash_segwit(tx, input_index, witness_script, value, sighash_type)
        return verify_strict_ecdsa(sighash, signature[:-1], pubkey)
    except Exception:
        return False


def create_p2wsh_witness_stack(signature: bytes, witness_script: bytes) -> list[bytes]:
    """Create witness stack for P2WSH input.

    For timelocked scripts (CLTV), the witness is: [signature, witness_script]

    Args:
        signature: DER signature with sighash byte
        witness_script: The witness script (e.g., freeze script)

    Returns:
        Witness stack: [signature, witness_script]
    """
    return [signature, witness_script]


# Re-export from jmcore for backward compatibility
__all__ = [
    "ParsedTransaction",
    "Transaction",
    "TransactionSigningError",
    "TxInput",
    "TxOutput",
    "compute_sighash_segwit",
    "create_p2wpkh_script_code",
    "create_p2wsh_witness_stack",
    "create_witness_stack",
    "deserialize_transaction",
    "encode_varint",
    "hash256",
    "read_varint",
    "sign_p2wpkh_input",
    "sign_p2wsh_input",
    "verify_p2wpkh_signature",
    "verify_p2wsh_signature",
]
