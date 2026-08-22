#!/usr/bin/env python3
"""witness.py - BAHI witness keys + signing.
Witness keys are HMAC-SHA256 derived from a group passphrase + witness name.
No crypto deps, deterministic, offline. Honest boundary: this is a structural
witness protocol (two parties hold independent keys), not a security audit."""
import hashlib, hmac, json

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
    """Return a witness entry that carries the signer's NAME alongside the
    signature, so an offline verifier with the witness's key can check it."""
    return {"name": witness, "sig": sign(payload, passphrase, witness)}