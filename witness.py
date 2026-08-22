#!/usr/bin/env python3
"""witness.py - BAHI witness keys + signing.

Witness signatures are HMAC-SHA256 over the meeting root, keyed by a random
per-witness key generated at meeting close (new_key()). No crypto deps,
deterministic, offline.

Honest boundary: HMAC is SYMMETRIC. In this prototype the witness keys are
stored in the chain file so an offline verifier can check signatures, which
means a bookkeeper with full file control can still forge both a key and a
signature. This removes the previous "hardcoded passphrase in source" hole
(anyone could forge just by reading the repo) and gives each witness a
distinct key, but it is NOT non-repudiation. Production path: asymmetric keys
(the witness holds a private key, the chain stores only public keys) -- a
documented roadmap item that requires a crypto dependency.
"""
import hashlib, hmac, json, os


def new_key():
    """Generate a fresh random 256-bit per-witness key (hex)."""
    return os.urandom(32).hex()


def sign(payload, key):
    """HMAC-SHA256 signature of the canonical JSON payload under `key` (hex)."""
    blob = json.dumps(payload, sort_keys=True)
    return hmac.new(bytes.fromhex(key), blob.encode("utf-8"), hashlib.sha256).hexdigest()


def verify(payload, sig, key):
    """Constant-time signature check under `key` (hex)."""
    return hmac.compare_digest(sign(payload, key), sig)


def sign_entry(payload, key, name):
    """Return a witness entry binding the signer's name, key, and signature."""
    return {"name": name, "key": key, "sig": sign(payload, key)}
