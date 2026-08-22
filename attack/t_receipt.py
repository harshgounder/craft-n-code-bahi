#!/usr/bin/env python3
"""t_receipt.py - verify_receipt attack matrix.
Every reason-code path plus mutation cases against a valid receipt.
"""
import sys, os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain, receipt_payload, verify_receipt, MIN_WITNESSES
from witness import sign

T = "2026-08-02T10:00:00"

def make(setup="default"):
    c = BahiChain("G-RAJ-042")
    c.add_event(1, "loan", "Kavita", 20000, T)
    c.close_meeting("M06", T)
    c.roots["M06"]["witnesses"] += [sign({"root": c.roots["M06"]["root_hash"], "meeting": "M06"}, "pass-Meera", "Meera"),
                                    sign({"root": c.roots["M06"]["root_hash"], "meeting": "M06"}, "pass-Laxmi", "Laxmi")]
    c.add_event(3, "contribution", "Sita", 10000, T)
    c.add_event(4, "contribution", "Geeta", 10000, T)
    c.add_event(5, "contribution", "Reema", 10000, T)
    c.add_event(6, "repayment", "Kavita", 10000, T)
    c.add_event(7, "loan", "Asha", 50000, T)
    c.add_event(8, "contribution", "Sita", 10000, T)
    root = c.close_meeting("M07", T)
    root["witnesses"] += [sign({"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera"),
                          sign({"root": root["root_hash"], "meeting": "M07"}, "pass-Laxmi", "Laxmi")]
    if setup == "honest":
        return c, root
    if setup == "wsig-fake":
        root["witnesses"] = ["aaa", "bbb"]          # garbage signature strings
    elif setup == "wsig-dupe":
        root["witnesses"] = ["sig-Meera", "sig-Meera"]  # same string twice, 2 entries
    elif setup == "wsig-oneparty":
        root["witnesses"] = ["sig-" + sign({"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera"),
                             "sig-" + sign({"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera")]
    elif setup == "wsig-empty":
        root["witnesses"] = []
    elif setup == "wsig-unicode":
        root["witnesses"] = ["Meera ✓", "Laxmi ✓"]
    elif setup == "wsig-dupname":
        root["witnesses"] = [sign({"root": root["root_hash"], "meeting": "M07"}, "pass-Meera", "Meera")] * 2
    return c, root

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.001 honest chain + receipt -> MATCH", ok and det == "MATCH", det)

    # -------- witness signature validity (the core finding) --------
    for setup in ("wsig-fake", "wsig-dupe", "wsig-oneparty", "wsig-unicode", "wsig-dupname"):
        c, root = make(setup)
        r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
        ok, det = verify_receipt(c, r)
        t("VULN.recv.wsig.%s MATCH with %s" % (setup, setup.replace("wsig-", "")),
          ok and det == "MATCH",
          "verify_receipt NEVER validates witness signatures: no witness.verify() call anywhere; any 2 strings pass quorum")
    c, root = make("wsig-empty")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.wsig.empty 0 witnesses -> quorum-fail", not ok and "quorum-fail" in det, det)

    # quorum count boundaries (real quorum failures)
    c, root = make("honest")
    root["witnesses"] = [root["witnesses"][0]]
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.quorum.001 chain 1 witness -> quorum-fail", not ok and "quorum-fail" in det, det)
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    r["witnesses"] = [root["witnesses"][0]]
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.quorum.002 receipt 1 witness -> quorum-fail", not ok and "quorum-fail" in det, det)
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    r["witnesses"] = []
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.quorum.003 receipt 0 witnesses -> quorum-fail", not ok and "quorum-fail" in det, det)
    # subset direction: chain subset of receipt is OK (receipt sigs not on chain fail)
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    r["witnesses"] = root["witnesses"] + ["extracopy"]
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.quorum.004 extra receipt witness -> witness-signature-differs", not ok and "differs" in det, det)

    # -------- receipt field mutations --------
    cases = [
        ("group", "G-OTHER", "group-mismatch"),
        ("meeting", "M99", "meeting-root-missing"),
        ("meeting", "M06", "FORK"),            # receipt for a DIFFERENT real meeting
        ("root", "f" * 64, "FORK"),
        ("root_seq", 999, "meeting-close-missing"),
        ("root_seq", 2, "FORK"),               # M06's close seq bound to M07 receipt -> root_seq collides with M06 close -> events-after-close
        ("member", "Other Member", "member-fail"),  # PR4: member now BOUND (fixed)
        ("root_ts", "2020-01-01", "MATCH"),    # ts not bound (still a gap)
        ("witnesses", [], "quorum-fail"),
    ]
    for field, val, expect in cases:
        c, root = make("honest")
        r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
        r[field] = val
        ok, det = verify_receipt(c, r)
        if expect == "MATCH":
            t("VULN.recv.field.%s (receipt %s NOT bound)" % (field, field),
              ok and det == "MATCH", "%s=%r still MATCHes: receipt payload field is not verified" % (field, val))
        elif expect == "member-fail":
            t("SAFE.recv.field.%s (PR4 member binding FIXED)" % field,
              not ok and ("member" in det or "FORK" in det), "%s=%r -> %s" % (field, val, det))
        elif expect == "FORK":
            t("SAFE.recv.field.%s -> FORK/events-after-close" % field,
              not ok and ("FORK" in det or "events-after-close" in det), det)
        else:
            t("SAFE.recv.field.%s -> %s" % (field, expect), not ok and expect in det, det)
    # extra unknown receipt fields are ignored
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    r["admin"] = "delete-evidence-flag"
    ok, det = verify_receipt(c, r)
    t("VULN.recv.field.extra unknown receipt fields ignored", ok and det == "MATCH",
      "receipts accept arbitrary extra fields without breaking binding")

    # -------- receipt type confusion --------
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    r["meeting"] = 12345
    try:
        ok, det = verify_receipt(c, r)
        t("VULN.recv.type.001 int meeting id tolerated", not ok and "meeting-root-missing" in det, det)
    except Exception as e:
        t("VULN.recv.type.001 int meeting id tolerated", False, "%s: %r" % (type(e).__name__, e))
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    r["witnesses"] = "notalist"
    try:
        ok, det = verify_receipt(c, r)
        t("VULN.recv.type.002 witnesses as string tolerated", not ok, "det=%s" % det)
    except Exception as e:
        t("VULN.recv.type.002 witnesses as string tolerated", False, "%s: %r" % (type(e).__name__, e))
    c, root = make("honest")
    r = {"group": "G-RAJ-042", "meeting": "M07", "root": root["root_hash"],
         "root_seq": root["root_seq"], "witnesses": None}
    try:
        ok, det = verify_receipt(c, r)
        t("chain.recv.type.003 witnesses None tolerated", not ok, det)
    except Exception as e:
        t("chain.recv.type.003 witnesses None tolerated", False, "%s: %r" % (type(e).__name__, e))

    # -------- missing receipt fields (crash check) --------
    base = {"group": "G-RAJ-042", "meeting": "M07", "root": root["root_hash"],
            "root_seq": root["root_seq"], "member": "Sita", "root_ts": T, "witnesses": root["witnesses"]}
    for missing in ("group", "meeting", "root", "root_seq", "witnesses", "member"):
        c, root = make("honest")
        r = dict(base)
        # re-fetch real values
        r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
        del r[missing]
        try:
            ok, det = verify_receipt(c, r)
            if missing == "member":
                t("SAFE.recv.missing.%s graceful fail (PR4 member binding FIXED)" % missing,
                  not ok and "member" in det, "receipt without %r -> %s" % (missing, det))
            else:
                t("SAFE.recv.missing.%s graceful fail" % missing, not ok and det != "", det)
        except Exception as e:
            t("SAFE.recv.missing.%s graceful fail" % missing, False, "%s: %r" % (type(e).__name__, e))
    # receipt = None / not a dict -> CRASH (violates 'never crashes')
    try:
        ok, det = verify_receipt(c, None)
        t("VULN.recv.missing.none-receipt crash", False, "no exception (test expects AttributeError)")
    except AttributeError as e:
        t("VULN.recv.missing.none-receipt crash", True,
          "AttributeError %r: verify_receipt(None) crashes: receipt.get() on None" % (e,))
    except Exception as e:
        t("VULN.recv.missing.none-receipt crash", True, "%s: %r" % (type(e).__name__, e))
    try:
        ok, det = verify_receipt(c, "string-receipt")
        t("VULN.recv.missing.str-receipt crash", False, "no exception (test expects AttributeError)")
    except AttributeError as e:
        t("VULN.recv.missing.str-receipt crash", True,
          "AttributeError %r: str receipt crashes: .get() on str" % (e,))
    except Exception as e:
        t("VULN.recv.missing.str-receipt crash", True, "%s: %r" % (type(e).__name__, e))

    # -------- chain-level attacks against a held receipt --------
    # (a) two MEETING-CLOSE events with same seq target
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    c.events[-1]["seq"] = c.events[-2]["seq"]  # collapse close seq: terminality + close_seqs checks
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.chain.001 duplicate close seq -> FORK", not ok and "FORK" in det, det)
    # (b) MEETING-CLOSE type copied onto an earlier event (fake close in middle)
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    c.events[3]["type"] = "MEETING-CLOSE"
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.chain.002 fake MEETING-CLOSE mid-chain -> FORK", not ok and "FORK" in det, det)
    # (c) move close earlier: two closes, receipt bound to LAST close only
    c, root = make("honest")
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    c.add_event(100, "contribution", "Ghost", 1, T)
    c.close_meeting("M07b", T)
    c.roots["M07b"]["witnesses"] += ["x", "y"]
    ok, det = verify_receipt(c, r)
    t("SAFE.recv.chain.003 later close invalidates earlier receipt", not ok and "events-after-close" in det, det)
    # (d) receipt for the SECOND close of same meeting id (root overwritten) - doc-only
    c, root = make("honest")
    old_meta = dict(c.roots["M07"])
    c.close_meeting("M07", T)  # same id again -> roots overwritten, receipt FORKs
    r = receipt_payload("G-RAJ-042", "M07", root, "Sita")
    ok, det = verify_receipt(c, r)
    t("VULN.recv.chain.004 re-close same meeting id orphans old receipts", not ok and "FORK" in det,
      "close_meeting('M07') overwrites M07 root metadata: every member holding the ORIGINAL M07 receipt now FORKs")

    return R