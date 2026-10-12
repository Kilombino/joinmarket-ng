"""
Test that validates our fidelity bond proofs are compatible with the reference implementation.

This test will run in the e2e environment where both implementations are available.
"""

import base64
import struct

import pytest
from bitcointx.core.key import CKey
from jmcore.crypto import bitcoin_message_hash_bytes

pytestmark = pytest.mark.reference


def _sign_message_bitcoin(private_key: CKey, message: bytes) -> bytes:
    """Sign a message using Bitcoin message signing format."""
    msg_hash = bitcoin_message_hash_bytes(message)
    return private_key.sign(msg_hash, _ecdsa_sig_grind_low_r=False)


def _pad_signature(sig_der: bytes, target_len: int = 72) -> bytes:
    """Pad DER signature to fixed length for wire format."""
    if len(sig_der) > target_len:
        raise ValueError(f"Signature too long: {len(sig_der)} > {target_len}")
    return sig_der.rjust(target_len, b"\xff")


def create_bond_proof_our_implementation(
    privkey: CKey,
    pubkey: bytes,
    maker_nick: str,
    taker_nick: str,
    txid: str,
    vout: int,
    locktime: int,
    cert_expiry_blocks: int = 2016 * 52,
) -> str:
    """Create bond proof using our implementation logic."""
    cert_pub = pubkey
    utxo_pub = pubkey
    cert_expiry_encoded = cert_expiry_blocks // 2016

    # 1. Nick signature - signs "(taker_nick|maker_nick)"
    nick_msg = (taker_nick + "|" + maker_nick).encode("ascii")
    nick_sig = _sign_message_bitcoin(privkey, nick_msg)
    nick_sig_padded = _pad_signature(nick_sig, 72)

    # 2. Certificate signature - self-signed
    cert_msg = (
        b"fidelity-bond-cert|"
        + cert_pub
        + b"|"
        + str(cert_expiry_encoded).encode("ascii")
    )
    cert_sig = _sign_message_bitcoin(privkey, cert_msg)
    cert_sig_padded = _pad_signature(cert_sig, 72)

    # 3. Pack the proof
    txid_bytes = bytes.fromhex(txid)
    proof_data = struct.pack(
        "<72s72s33sH33s32sII",
        nick_sig_padded,
        cert_sig_padded,
        cert_pub,
        cert_expiry_encoded,
        utxo_pub,
        txid_bytes,
        vout,
        locktime,
    )

    return base64.b64encode(proof_data).decode("ascii")


def test_bond_proof_validates_with_reference_implementation():
    """
    Test that bond proofs created with our implementation can be validated
    by the reference implementation's FidelityBondProof parser.

    This is the critical compatibility test - if this passes, it means
    reference orderbook watchers SHOULD be able to validate our bonds.
    """
    # Import reference implementation
    try:
        import os
        import sys

        ref_path = os.path.join(
            os.path.dirname(__file__), "../../joinmarket-clientserver/src"
        )
        if ref_path not in sys.path:
            sys.path.insert(0, ref_path)
        from jmclient.fidelity_bond import FidelityBondProof
    except ImportError as e:
        pytest.skip(f"Reference implementation not available: {e}")

    # Create test bond
    privkey = CKey(b"\x01" * 32)
    pubkey = bytes(privkey.pub)

    maker_nick = "J52TestMaker"
    taker_nick = "J5TestTaker"
    txid = "a" * 64
    vout = 0
    locktime = 1768435200

    # Create proof using our implementation
    our_proof = create_bond_proof_our_implementation(
        privkey=privkey,
        pubkey=pubkey,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        txid=txid,
        vout=vout,
        locktime=locktime,
    )

    assert len(our_proof) == 336  # base64 of 252 bytes

    # Validate with reference implementation
    validated_proof = FidelityBondProof.parse_and_verify_proof_msg(
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        data=our_proof,
    )

    # Verify all fields match
    assert validated_proof.maker_nick == maker_nick
    assert validated_proof.taker_nick == taker_nick


def create_bond_proof_with_certificate(
    utxo_privkey: CKey,
    utxo_pubkey: bytes,
    cert_privkey: CKey,
    cert_pubkey: bytes,
    cert_signature: bytes,
    cert_expiry_encoded: int,
    maker_nick: str,
    taker_nick: str,
    txid: str,
    vout: int,
    locktime: int,
) -> str:
    """
    Create bond proof with a pre-signed certificate (cold storage mode).

    This simulates what happens when:
    1. User generates a hot keypair (cert_privkey/cert_pubkey)
    2. User signs the certificate message with their cold wallet (utxo_privkey)
    3. Maker uses the pre-signed certificate to create proofs

    Args:
        utxo_privkey: Cold wallet private key (only used for reference, not in real flow)
        utxo_pubkey: Cold wallet public key (from bond UTXO)
        cert_privkey: Hot wallet private key (for signing nick messages)
        cert_pubkey: Hot wallet public key (certificate subject)
        cert_signature: Pre-signed certificate (signed by utxo_privkey)
        cert_expiry_encoded: Certificate expiry in 2016-block periods
        maker_nick: Maker's JoinMarket nick
        taker_nick: Taker's nick (for ownership proof)
        txid: Bond UTXO txid
        vout: Bond UTXO vout
        locktime: Bond locktime
    """
    # 1. Nick signature - signs "(taker_nick|maker_nick)" with HOT wallet key
    nick_msg = (taker_nick + "|" + maker_nick).encode("ascii")
    nick_sig = _sign_message_bitcoin(cert_privkey, nick_msg)
    nick_sig_padded = _pad_signature(nick_sig, 72)

    # 2. Certificate signature - pre-signed by COLD wallet (utxo key)
    cert_sig_padded = _pad_signature(cert_signature, 72)

    # 3. Pack the proof
    txid_bytes = bytes.fromhex(txid)
    proof_data = struct.pack(
        "<72s72s33sH33s32sII",
        nick_sig_padded,
        cert_sig_padded,
        cert_pubkey,  # Certificate pubkey (hot wallet)
        cert_expiry_encoded,
        utxo_pubkey,  # UTXO pubkey (cold wallet)
        txid_bytes,
        vout,
        locktime,
    )

    return base64.b64encode(proof_data).decode("ascii")


def test_bond_proof_with_ascii_certificate_validates_with_reference():
    """
    Test that bond proofs with ASCII-format certificates (cold storage / Sparrow)
    are validated by the reference implementation.

    This is the critical test for cold storage support. The ASCII format uses
    the hex-encoded pubkey in the certificate message:
        b'fidelity-bond-cert|<hex_pubkey>|<expiry>'

    Instead of the binary format:
        b'fidelity-bond-cert|<raw_pubkey_bytes>|<expiry>'

    The reference implementation (fidelity_bond.py lines 138-140) tries BOTH formats,
    so ASCII-signed certificates should validate.
    """
    try:
        import os
        import sys

        ref_path = os.path.join(
            os.path.dirname(__file__), "../../joinmarket-clientserver/src"
        )
        if ref_path not in sys.path:
            sys.path.insert(0, ref_path)
        from jmclient.fidelity_bond import FidelityBondProof
    except ImportError as e:
        pytest.skip(f"Reference implementation not available: {e}")

    # Create UTXO keypair (cold wallet - would be on hardware wallet)
    utxo_privkey = CKey(b"\x01" * 32)
    utxo_pubkey = bytes(utxo_privkey.pub)

    # Create certificate keypair (hot wallet)
    cert_privkey = CKey(b"\x02" * 32)
    cert_pubkey = bytes(cert_privkey.pub)

    cert_expiry_encoded = 52  # ~2 years

    # Create ASCII format certificate message (what Sparrow would sign)
    # This is the key difference from binary format!
    ascii_cert_msg = (
        b"fidelity-bond-cert|"
        + cert_pubkey.hex().encode("ascii")  # Hex-encoded pubkey
        + b"|"
        + str(cert_expiry_encoded).encode("ascii")
    )

    # Sign with cold wallet key (simulating Sparrow signing)
    cert_signature = _sign_message_bitcoin(utxo_privkey, ascii_cert_msg)

    maker_nick = "J52ColdMaker"
    taker_nick = "J5TestTaker"
    txid = "c" * 64
    vout = 0
    locktime = 1769904000

    # Create proof using the ASCII-signed certificate
    proof = create_bond_proof_with_certificate(
        utxo_privkey=utxo_privkey,
        utxo_pubkey=utxo_pubkey,
        cert_privkey=cert_privkey,
        cert_pubkey=cert_pubkey,
        cert_signature=cert_signature,
        cert_expiry_encoded=cert_expiry_encoded,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        txid=txid,
        vout=vout,
        locktime=locktime,
    )

    # Validate with reference implementation
    # This should pass because reference tries both binary and ASCII formats
    validated_proof = FidelityBondProof.parse_and_verify_proof_msg(
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        data=proof,
    )

    # Verify all fields match
    assert validated_proof.maker_nick == maker_nick
    assert validated_proof.taker_nick == taker_nick
    assert validated_proof.utxo[0] == bytes.fromhex(txid)
    assert validated_proof.utxo[1] == vout
    assert validated_proof.locktime == locktime
    assert validated_proof.cert_pub == cert_pubkey  # Hot wallet pubkey
    assert validated_proof.utxo_pub == utxo_pubkey  # Cold wallet pubkey


def test_bond_proof_with_binary_certificate_validates_with_reference():
    """
    Test that bond proofs with binary-format certificates (traditional hot wallet)
    are validated by the reference implementation.

    This is the traditional format where the certificate message contains raw pubkey bytes:
        b'fidelity-bond-cert|<raw_pubkey_bytes>|<expiry>'
    """
    try:
        import os
        import sys

        ref_path = os.path.join(
            os.path.dirname(__file__), "../../joinmarket-clientserver/src"
        )
        if ref_path not in sys.path:
            sys.path.insert(0, ref_path)
        from jmclient.fidelity_bond import FidelityBondProof
    except ImportError as e:
        pytest.skip(f"Reference implementation not available: {e}")

    # Create UTXO keypair (in hot wallet mode, this is the same as cert keypair)
    utxo_privkey = CKey(b"\x01" * 32)
    utxo_pubkey = bytes(utxo_privkey.pub)

    # In traditional self-signed mode, cert == utxo
    cert_privkey = utxo_privkey
    cert_pubkey = utxo_pubkey

    cert_expiry_encoded = 52

    # Create BINARY format certificate message (traditional format)
    binary_cert_msg = (
        b"fidelity-bond-cert|"
        + cert_pubkey  # Raw pubkey bytes
        + b"|"
        + str(cert_expiry_encoded).encode("ascii")
    )

    # Self-sign with the same key
    cert_signature = _sign_message_bitcoin(utxo_privkey, binary_cert_msg)

    maker_nick = "J52HotMaker"
    taker_nick = "J5TestTaker"
    txid = "d" * 64
    vout = 0
    locktime = 1769904000

    # Create proof using the binary-signed certificate
    proof = create_bond_proof_with_certificate(
        utxo_privkey=utxo_privkey,
        utxo_pubkey=utxo_pubkey,
        cert_privkey=cert_privkey,
        cert_pubkey=cert_pubkey,
        cert_signature=cert_signature,
        cert_expiry_encoded=cert_expiry_encoded,
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        txid=txid,
        vout=vout,
        locktime=locktime,
    )

    # Validate with reference implementation
    validated_proof = FidelityBondProof.parse_and_verify_proof_msg(
        maker_nick=maker_nick,
        taker_nick=taker_nick,
        data=proof,
    )

    # Verify all fields match
    assert validated_proof.maker_nick == maker_nick
    assert validated_proof.taker_nick == taker_nick
    assert validated_proof.cert_pub == cert_pubkey
    assert validated_proof.utxo_pub == utxo_pubkey
