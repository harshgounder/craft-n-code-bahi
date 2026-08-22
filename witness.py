#!/usr/bin/env python3
"""witness.py - BAHI witness keys + signing.

Witness keys are HMAC-SHA256 derived from a group passphrase + witness name.
No crypto deps, deterministic, offline.

Honest boundary (documented): HMAC is symmetric. Verifying a witness signature
requires that witness's key (or the group passphrase it was derived from), so an
offline member holding only a receipt cannot cryptographically check a witness
signature herself; she can check the RECEIPT ROOT against the recomputed chain
(the actual fraud signal). Witness signatures add a name-bound attestation that
is verifiable by anyone who holds the group passphrase (secretary, auditor,
federation node) - see verify_receipt(..., witness_keys=...).
"""
import hashlib, hmac, json

_SIG_HEX_LEN = 64
_HEX = set("0123456789abcdef")


def derive_key(passphrase, witness):
    return hmac.new(passphrase.encode("utf-8"), ("BAHI-WITNESS:" + witness).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def sign(payload, passphrase, witness):
    key = derive_key(passphrase, witness)
    blob = json.dumps(payload, sort_keys=True)
    return hmac.new(key.encode("utf-8"), blob.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(payload, sig, passphrase, witness):
    return hmac.compare_digest(sign(payload, passphrase, witness), sig)


def sign_entry(payload, passphrase, witness):
    """Return a name-bound witness record: {'witness': name, 'sig': hex}.

    Storing the witness name alongside the signature is what makes the
    attestation meaningful ("Meera and Laxmi signed", not "two opaque strings").
    """
    return {"witness": witness, "sig": sign(payload, passphrase, witness)}


def is_valid_sig(sig):
    """True if `sig` is a well-formed 64-char lowercase hex HMAC."""
    return isinstance(sig, str) and len(sig) == _SIG_HEX_LEN and set(sig) <= _HEX
