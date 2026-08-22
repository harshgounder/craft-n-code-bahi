#!/usr/bin/env python3
"""witness.py - BAHI witness keys + signing.

Two signing modes are supported:

1. HMAC-SHA256 (legacy, zero-dependency). Keys are derived from a group
   passphrase + witness name. Verifying a signature requires that witness's
   key (or the passphrase), so an offline member holding only a receipt cannot
   cryptographically check a legacy HMAC witness signature herself.

2. Ed25519 (asymmetric, recommended). Each witness holds a PRIVATE signing key
   and publishes a PUBLIC verify key that travels inside the witness record on
   the receipt. Any member holding the receipt can verify the signature herself
   - no shared secret, no key custody - because verification needs only the
   public key. This is the solution to the HMAC-symmetric caveat.

Honest boundary (documented, unchanged): Ed25519 gives offline verification
and non-repudiation (a witness cannot later deny signing, and no one else can
forge her signature), but it does NOT bind a public key to a real human. That
binding (who issued Meera's key, and is it really Meera) is an out-of-band
identity/KYC trust anchor - see docs/PRODUCT-DECISIONS.md, "Key management".

The Ed25519 path requires the `cryptography` package (pip install cryptography);
the HMAC path remains dependency-free. If `cryptography` is missing, every
Ed25519 call raises a clear RuntimeError instead of silently degrading.
"""
import base64
import binascii
import hashlib
import hmac
import json
import re

_SIG_HEX_LEN = 64
_HEX = set("0123456789abcdef")

try:  # optional asymmetric backend
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    _HAS_ED25519 = True
except Exception:  # pragma: no cover - exercised only on dependency-less hosts
    _HAS_ED25519 = False

_ED_PUB_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
# 64-byte Ed25519 signature -> 88 base64 chars with '==' padding
_ED_SIG_B64_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")


def _canonical_blob(payload):
    """Deterministic bytes signed by BOTH HMAC and Ed25519 paths.

    Same bytes for both modes: json.dumps(sort_keys=True) -> utf-8. A witness
    record that was signed over a given payload verifies under whichever mode
    the verifier has a key for.
    """
    return json.dumps(payload, sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# HMAC (legacy, zero-dependency)
# ---------------------------------------------------------------------------
def derive_key(passphrase, witness):
    return hmac.new(passphrase.encode("utf-8"), ("BAHI-WITNESS:" + witness).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def sign(payload, passphrase, witness):
    key = derive_key(passphrase, witness)
    return hmac.new(key.encode("utf-8"), _canonical_blob(payload), hashlib.sha256).hexdigest()


def verify(payload, sig, passphrase, witness):
    return hmac.compare_digest(sign(payload, passphrase, witness), sig)


def sign_entry(payload, passphrase, witness):
    """Return a name-bound HMAC witness record: {'witness': name, 'sig': hex}.

    Storing the witness name alongside the signature is what makes the
    attestation meaningful ("Meera and Laxmi signed", not "two opaque strings").
    """
    return {"witness": witness, "sig": sign(payload, passphrase, witness)}


def is_valid_sig(sig):
    """True if `sig` is a well-formed 64-char lowercase hex HMAC."""
    return isinstance(sig, str) and len(sig) == _SIG_HEX_LEN and set(sig) <= _HEX


# ---------------------------------------------------------------------------
# Ed25519 (asymmetric, recommended) - solves offline verification
# ---------------------------------------------------------------------------
def ed25519_available():
    return _HAS_ED25519


def _require_ed25519():
    if not _HAS_ED25519:
        raise RuntimeError(
            "Ed25519 witness signing requires the 'cryptography' package "
            "(pip install cryptography); the zero-dependency HMAC path "
            "(witness.sign_entry) remains available.")


def generate_keypair():
    """Return {'signing_key': <64-hex private>, 'verify_key': <64-hex public>}.

    The PRIVATE key stays with the witness (never serialized into the ledger or
    the receipt); the PUBLIC key is embedded in every witness record so any
    member can verify offline. This is the root of the fix for the HMAC-symmetric
    caveat: verification needs only the public half, which travels with the data.
    """
    _require_ed25519()
    sk = Ed25519PrivateKey.generate()
    sk_hex = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    vk_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {"signing_key": sk_hex, "verify_key": vk_hex}


def sign_entry_ed25519(payload, signing_key_hex, witness):
    """Sign `payload` with a witness's Ed25519 PRIVATE key.

    Returns {'witness': name, 'verify_key': <64-hex public>, 'sig': <base64>}.
    The public key is embedded so the recipient can verify without any secret.
    """
    _require_ed25519()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(signing_key_hex))
    sig = sk.sign(_canonical_blob(payload))
    vk_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {
        "witness": witness,
        "verify_key": vk_hex,
        "sig": base64.b64encode(sig).decode("ascii"),
    }


def verify_sig_ed25519(payload, sig_b64, verify_key_hex):
    """Verify an Ed25519 signature with ONLY the public key (no secret)."""
    if not _HAS_ED25519:
        return False
    try:
        vk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(verify_key_hex))
        vk.verify(base64.b64decode(sig_b64, validate=True), _canonical_blob(payload))
        return True
    except (InvalidSignature, ValueError, binascii.Error, TypeError):
        return False


def is_valid_verify_key(vk):
    """True if `vk` is a well-formed 64-char lowercase hex Ed25519 public key."""
    return isinstance(vk, str) and bool(_ED_PUB_HEX_RE.match(vk))


def is_valid_ed_sig(sig):
    """True if `sig` is a well-formed base64 Ed25519 signature (64 bytes)."""
    if not isinstance(sig, str) or not _ED_SIG_B64_RE.match(sig):
        return False
    try:
        return len(base64.b64decode(sig, validate=True)) == 64
    except binascii.Error:
        return False
