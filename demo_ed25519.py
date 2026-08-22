#!/usr/bin/env python3
"""demo_ed25519.py - show how asymmetric witness keys solve the HMAC caveat.

The old HMAC path left one gap: a member holding only a receipt could NOT
cryptographically verify a witness signature herself, because verifying HMAC
needs the shared secret. Ed25519 fixes it: each witness keeps a PRIVATE key
and publishes a PUBLIC key that rides inside the witness record on the receipt,
so ANY member can verify offline with no secret and no key custody.

This demo walks the whole loop and proves the member can:
  1. verify a genuine receipt offline (no keys), and
  2. detect a forged witness signature offline.

Run:  python demo_ed25519.py   (requires: pip install cryptography)
"""
import sys

from chain import BahiChain, receipt_payload, verify_receipt
from witness import generate_keypair, sign_entry_ed25519, ed25519_available

LINE = "-" * 72


def main():
    if not ed25519_available():
        print("cryptography not installed; run: pip install cryptography")
        return 1

    print(LINE)
    print("BAHI + Ed25519: offline witness verification demo")
    print(LINE)

    # 1. Witnesses generate keypairs. Private keys NEVER leave their devices.
    #    Public keys are shared and ride on every receipt.
    meera = generate_keypair()
    laxmi = generate_keypair()
    print("[1] Meera & Laxmi each generate an Ed25519 keypair.")
    print("    Meera public key :", meera["verify_key"][:24] + "...")
    print("    Laxmi public key :", laxmi["verify_key"][:24] + "...")
    print("    (private keys stay on their phones; only public keys are published)")

    # 2. The secretary closes a meeting; witnesses sign the root with PRIVATE keys.
    c = BahiChain("G-RAJ-042")
    t = "2026-08-02T10:00:00"
    c.add_event(1, "contribution", "Sita", 10000, t)
    c.add_event(2, "contribution", "Geeta", 10000, t)
    c.add_event(3, "loan", "Asha", 50000, t)
    root = c.close_meeting("M07", t)
    for name, kp in (("Meera", meera), ("Laxmi", laxmi)):
        root["witnesses"].append(
            sign_entry_ed25519({"root": root["root_hash"], "meeting": "M07"},
                               kp["signing_key"], name))
    print("[2] Meeting M07 closed. Witnesses signed the root with PRIVATE keys.")
    print("    Receipt witness record carries the PUBLIC key + signature:")
    print("   ", {k: (v[:16] + "..." if k == "sig" else v[:16] + "...")
                  for k, v in root["witnesses"][0].items()})

    # 3. Sita (a member) holds ONLY the receipt. She has NO keys.
    receipt = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
    print("[3] Sita receives a receipt. She holds NO signing keys.")

    ok, det = verify_receipt(c, receipt)   # no witness_keys passed
    print("[4] Sita verifies OFFLINE with only the receipt (no keys):", ok, det)

    # 5. The secretary tampered a witness signature -> Sita detects it offline.
    forged = dict(receipt)
    forged["witnesses"] = [dict(w) for w in receipt["witnesses"]]
    forged["witnesses"][0]["sig"] = "A" * 86 + "=="
    ok, det = verify_receipt(c, forged)
    print("[5] Forged witness signature -> Sita's offline check:", ok, det)

    print(LINE)
    print("What changed vs HMAC: verification needs only the PUBLIC key, which")
    print("travels with the receipt. No shared secret, no key custody, and the")
    print("witness cannot later deny signing (non-repudiation).")
    print()
    print("Remaining trust anchor (documented): a public key still must be bound")
    print("to a real person out-of-band (KYC / key registry) - see")
    print("docs/PRODUCT-DECISIONS.md 'Key management'. Ed25519 cannot solve that")
    print("by itself, and no signature scheme can.")
    print(LINE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
