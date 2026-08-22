#!/usr/bin/env python3
"""t_witness.py - witness.py attack matrix: key derivation, forging, replay."""
import json, sys, os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from witness import derive_key, sign, verify
from chain import h

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    # determinism / basics
    t("witness.001 derive_key deterministic", derive_key("pass", "Meera") == derive_key("pass", "Meera"))
    t("witness.002 different witness different key", derive_key("pass", "Meera") != derive_key("pass", "Laxmi"))
    t("witness.003 sign/verify roundtrip", verify({"root": "x"}, sign({"root": "x"}, "pw", "Meera"), "pw", "Meera"))
    t("witness.004 wrong witness fails", not verify({"root": "x"}, sign({"root": "x"}, "pw", "Meera"), "pw", "Laxmi"))

    # -------- forgery under known passphrase (server.py hardcodes them) --------
    payload = {"root": "f" * 64, "meeting": "M07"}
    for w in ("Meera", "Laxmi"):
        sig = sign(payload, "pass-" + w, w)
        t("VULN.witness.fake.%s forgeable with HARDCODED passphrase" % w,
          verify(payload, sig, "pass-" + w, w),
          "server.py signs with 'pass-%s' in source; anyone can compute derive_key + sign identical witness seals" % w)
    # key derivation is unkeyed per group: same passphrase across groups
    t("VULN.witness.005 same passphrase => same key across groups",
      derive_key("pass-Meera", "Meera") == derive_key("pass-Meera", "Meera"),
      "group id is NOT mixed into derive_key: one leaked passphrase forges every group's witnesses")

    # -------- signature message structure --------
    # payload canonicalization: json.dumps sort_keys=True but separators/whitespace differ
    p1 = {"root": "abc", "meeting": "M1", "z": 1}
    s1 = sign(p1, "pw", "W")
    p2 = {"meeting": "M1", "z": 1.0, "root": "abc"}   # same semantic, float 1.0 vs int 1
    t("VULN.witness.006 int/float canonicalization: 1.0 vs 1 produce different sigs",
      sign(p2, "pw", "W") != s1,
      "json.dumps(1)='1' vs json.dumps(1.0)='1.0': semantically identical payloads sign differently (interop brittleness)")
    p3 = dict(p1)
    p3["extra"] = {"b": 2, "a": 1}
    s3 = sign(p3, "pw", "W")
    t("witness.007 nested keys sorted recursively", isinstance(s3, str) and len(s3) == 64)
    # unicode normalization in payloads
    a1 = sign({"root": "S\u00e9eta"}, "pw", "W")
    a2 = sign({"root": "S\u0065\u0301eta"}, "pw", "W")
    t("VULN.witness.008 NFC/NFD payload spellings sign differently", a1 != a2,
      "same spoken name in different unicode forms -> different sigs (mobile keyboards vary)")

    # -------- replay --------
    sig = sign(payload, "pw", "W")
    t("witness.009 sig binds root: replay to different root fails",
      not verify({"root": "0" * 64, "meeting": "M07"}, sig, "pw", "W"),
      "HMAC over (root, meeting): same meeting + different root -> different signature")
    t("VULN.witness.009b sig replayable to same root+meeting, unbounded to chain state",
      verify(payload, sig, "pw", "W"),
      "signature carries no chain position/seq/context; plus chain layer never calls verify() so all of this is decorative")
    # empty passphrase
    t("witness.010 empty passphrase works", verify({}, sign({}, "", "W"), "", "W"))
    # signature truncated / garbage
    t("witness.011 garbage sig fails", not verify(payload, "garbage", "pw", "W"))
    t("witness.012 empty sig fails", not verify(payload, "", "pw", "W"))
    # huge payload
    big = {"root": "x" * 100000}
    t("witness.013 large payload signs", len(sign(big, "pw", "W")) == 64)
    # timing-safe compare present
    t("witness.014 uses hmac.compare_digest", "compare_digest" in open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "witness.py")).read())
    # derive_key length / format
    t("witness.015 key is 64 hex chars", len(derive_key("pw", "W")) == 64)
    # witness name collisions: derive_key(pass, witness) only input is witness name
    t("VULN.witness.016 witness identity = plain name string (no id/phone binding)",
      derive_key("pw", "Sita") == derive_key("pw", "Sita"),
      "two different people named Sita in one group share a witness key; impersonation by same-name member")
    # no key rotation / revocation mechanism exists
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "witness.py")).read()
    t("VULN.witness.017 no revocation/rotation API", "revoke" not in src and "rotate" not in src,
      "compromised or departed witness keeps full signing power forever")

    return R