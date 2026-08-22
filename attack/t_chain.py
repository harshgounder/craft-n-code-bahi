#!/usr/bin/env python3
"""t_chain.py - chain integrity attack matrix against chain.py.
Expectation style: "VULN." = flaw expected & confirmed; "SAFE." = defense must hold.
"""
import hashlib, json, os, tempfile
import sys, os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain, h, _norm_amount, MIN_WITNESSES, receipt_payload, verify_receipt
from witness import sign

T = "2026-08-02T10:00:00"

def make_chain(n=7, group="G-RAJ-042", close=True, sigs=("Meera", "Laxmi")):
    c = BahiChain(group)
    types = ["contribution", "contribution", "contribution", "repayment",
             "loan", "contribution", "contribution"]
    members = ["Sita", "Geeta", "Reema", "Kavita", "Asha", "Sita", "Sita"]
    amounts = [10000, 10000, 10000, 10000, 50000, 10000, 10000]
    for i in range(n):
        c.add_event(i + 1, types[i % 7], members[i % 7], amounts[i % 7], T)
    root = None
    if close:
        root = c.close_meeting("M07", T)
        for w in sigs:
            root["witnesses"].append(sign({"root": root["root_hash"], "meeting": "M07"}, "pass-" + w, w))
    return c, root

def full_recompute(c):
    """Recompute every event hash from the first event (attacker with file control).
    Uses the CURRENT hash formula (group inside, PR10)."""
    prev = h("GENESIS", c.group_id)
    for ev in c.events:
        ev["prev"] = prev
        ev["hash"] = h(prev, c.group_id, ev["seq"], ev["type"], ev["member"],
                       _norm_amount(ev["amount_paise"]), ev["ts"])
        prev = ev["hash"]

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))
        return bool(ok)

    # ---------- hash primitive ----------
    v1 = h("a", "b")
    m = hashlib.sha256()
    m.update(b"a"); m.update(b"\x1f"); m.update(b"b"); m.update(b"\x1f")
    t("chain.H.001 independent recompute matches h()", v1 == m.hexdigest(), v1)
    t("chain.H.002 deterministic across calls", h("a", "b") == v1)
    t("chain.H.003 distinct inputs distinct hashes", h("x") != h("y"))
    t("chain.H.004 empty part allowed", isinstance(h("a", ""), str))
    t("chain.H.005 int part hashes like str part (type collapse)",
      h(1, "x") == h("1", "x"), "int 1 == str '1' -> same digest: field types interchangeable")
    t("chain.H.006 separator-injection collision: h('a\\x1fb','c') == h('a','b\\x1fc')",
      h("a\x1fb", "c") == h("a", "b\x1fc"),
      "parts containing byte 0x1f make part boundaries ambiguous: two DIFFERENT (tuple) inputs collide")
    t("chain.H.007 unicode deterministic", h("Sita", "₹100") == h("Sita", "₹100"))
    nfc = "S\u00e9eta"                      # precomposed é
    nfd = "S\u0065\u0301eta"               # decomposed e + combining acute
    t("chain.H.008 NFC vs NFD spellings hash differently (byte-exact, no normalization)",
      h(nfc) != h(nfd), "same spoken name, different bytes -> receipt/chain mismatch on spelling (interop edge)")

    # ---------- amount validation (PR10: bool/float/str rejected) ----------
    t("SAFE.amount.001 negative int rejected", _norm_amount(-1) is None)
    t("SAFE.amount.002 zero accepted", _norm_amount(0) == 0)
    t("SAFE.amount.003 non-integral float rejected (PR10)", _norm_amount(1.5) is None and _norm_amount(1.9) is None)
    t("SAFE.amount.004 bool rejected (PR10)", _norm_amount(True) is None and _norm_amount(False) is None)
    # documented design (chain.py _norm_amount): integral numeric strings
    # normalize to int; non-numeric strings are rejected
    t("SAFE.amount.005 integral numeric string normalizes", _norm_amount("1000") == 1000)
    t("SAFE.amount.006 non-numeric string rejected", _norm_amount("abc") is None and _norm_amount("-3") is None)
    c = BahiChain("G")
    try:
        ev = c.add_event(1, "contribution", "Sita", "100", T)
        t("SAFE.amount.007 string amount normalized to int", ev["amount_paise"] == 100 and isinstance(ev["amount_paise"], int), str(ev["amount_paise"]))
    except ValueError:
        t("SAFE.amount.007 string amount normalized to int", False, "raised")
    try:
        c.add_event(2, "contribution", "Sita", True, T)
        t("SAFE.amount.008 add_event rejects bool amount (PR10)", False, "bool accepted")
    except ValueError:
        t("SAFE.amount.008 add_event rejects bool amount (PR10)", True)
    # _norm_amount returns None for invalid (sentinel), never raises for junk
    for bad in (-5, "abc", 1.5, None, [], {}, {"x": 1}):
        got = _norm_amount(bad)
        if bad == 1.5:
            t("SAFE.amount.009 float rejected (PR10)", got is None, "got %r" % (got,))
        else:
            t("SAFE.amount.009 reject junk %r (None sentinel)" % (bad,), got is None,
              "got %r" % (got,))
    t("SAFE.amount.010 NaN rejected", _norm_amount(float("nan")) is None)

    # ---------- member / type / ts validation ----------
    try:
        c.add_event(9, "contribution", "", 10, T)
        t("SAFE.member.001 empty member rejected", False)
    except ValueError:
        t("SAFE.member.001 empty member rejected", True)
    try:
        c.add_event(10, "contribution", 123, 10, T)
        t("SAFE.member.002 non-str member rejected", False)
    except ValueError:
        t("SAFE.member.002 non-str member rejected", True)
    c2 = BahiChain("G")
    try:
        c2.add_event(1, "contribution", "   ", 10, T)
        t("SAFE.member.003 whitespace-only member rejected (PR10)", False)
    except ValueError:
        t("SAFE.member.003 whitespace-only member rejected (PR10)", True)
    c3 = BahiChain("G")
    try:
        c3.add_event(1, "any-garbage-type-here", "Sita", 10, T)
        t("SAFE.type.001 arbitrary event type rejected (PR10)", False)
    except ValueError:
        t("SAFE.type.001 arbitrary event type rejected (PR10)", True)
    try:
        c3.add_event(2, "loan", "Sita", 10, None)
        t("SAFE.ts.001 None timestamp rejected (PR10)", False)
    except (TypeError, ValueError):
        t("SAFE.ts.001 None timestamp rejected (PR10)", True)
    try:
        c3.add_event(3, "loan", "Sita", 10, {"a": 1})
        t("SAFE.ts.002 dict timestamp rejected (PR10)", False)
    except (TypeError, ValueError):
        t("SAFE.ts.002 dict timestamp rejected (PR10)", True)

    # ---------- chain construction / seq handling (PR10: strict monotonic) ----------
    c4 = BahiChain("G")
    c4.add_event(1, "contribution", "Sita", 100, T)
    try:
        c4.add_event(2, "contribution", "Sita", 200, T)
        t("chain.seq.001 correction (same identity) allowed", True)
    except Exception as e:
        t("chain.seq.001 correction (same identity) allowed", False, repr(e))
    try:
        c4.add_event(2, "loan", "Ghost", 999, T)
        t("SAFE.seq.002 duplicate seq rejected (PR10)", False)
    except ValueError:
        t("SAFE.seq.002 duplicate seq rejected (PR10)", True)
    ok, _, _ = c4.verify()
    t("chain.seq.003 monotonic chain verifies OK", ok, "after PR10 strict seqs")
    c5 = BahiChain("G")
    try:
        c5.add_event(99, "contribution", "Sita", 100, T)
        t("SAFE.seq.004 out-of-order first seq rejected (PR10)", False)
    except ValueError:
        t("SAFE.seq.004 out-of-order first seq rejected (PR10)", True)
    c5.add_event(1, "contribution", "Sita", 100, T)
    r5 = c5.close_meeting("M1", T)
    t("chain.seq.005 close seq = next monotonic", r5["root_seq"] == 2,
      "root_seq %d (want 2)" % r5.get("root_seq"))
    ok5, _, _ = c5.verify()
    t("chain.seq.006 close chain verifies OK", ok5, "")

    # ---------- tamper matrix (naive edit, expect detection) ----------
    # field-level tamper on a single event index
    def poke(c, idx, field, value):
        c.events[idx][field] = value

    for midx, label in ((0, "first"), (len(make_chain()[0].events) // 2, "middle"), (len(make_chain()[0].events) - 1, "last")):
        for field, value, why in (
            ("amount_paise", 1, "event-hash-mismatch"),
            ("member", "Hacker", "event-hash-mismatch"),
            ("type", "fraud", "event-hash-mismatch"),
            ("ts", "1999-01-01", "event-hash-mismatch"),
            ("seq", 9999, "event-hash-mismatch"),
            ("prev", "0" * 64, "event-hash-mismatch"),
            ("hash", "0" * 64, "event-hash-mismatch"),
        ):
            c, _ = make_chain()
            poke(c, midx, field, value)
            okv, bad_seq, whyv = c.verify()
            if field == "seq":
                # PR10: seq now validated during verify -> corrupt-file: bad seq
                t("SAFE.tamper.%s.%s (%s) caught" % (label, field, midx),
                  not okv and ("mismatch" in whyv or "corrupt-file" in whyv),
                  "ok=%s bad_seq=%s why=%s" % (okv, bad_seq, whyv))
            else:
                t("SAFE.tamper.%s.%s (%s)" % (label, field, midx), not okv and "mismatch" in whyv,
                  "ok=%s bad_seq=%s why=%s" % (okv, bad_seq, whyv))
        # group field IS part of the per-event hash now (PR10) -> detected
        c, _ = make_chain()
        poke(c, midx, "group", "G-OTHER-CLAN")
        okv, _, whyv = c.verify()
        t("SAFE.tamper.%s.group (%s) caught: group is hashed (PR10)" % (label, midx),
          not okv, "why=%s" % whyv)
    # swap adjacent
    for label, (i, j) in (("first-two", (0, 1)), ("middle", (3, 4)), ("last-two", (-2, -1))):
        c, _ = make_chain()
        c.events[i], c.events[j] = c.events[j], c.events[i]
        okv, bad_seq, whyv = c.verify()
        t("SAFE.swap.%s" % label, not okv and ("prev-hash-mismatch" in whyv or "event-hash-mismatch" in whyv or "corrupt-file" in whyv),
          "ok=%s bad_seq=%s why=%s" % (okv, bad_seq, whyv))
    # delete
    for label, idx in (("first", 0), ("second", 1), ("middle", 3), ("close", -1)):
        c, _ = make_chain()
        del c.events[idx]
        okv, bad_seq, whyv = c.verify()
        if label == "first":
            # PR11: genesis anchored now -> deleting the head breaks the anchor
            t("SAFE.del.first genesis anchored (PR11): deletion caught", not okv,
              "ok=%s why=%s" % (okv, whyv))
        elif label == "close":
            t("chain.del.%s verify() stays OK (no forward link to check)" % label, okv,
              "deleting the LAST event is invisible to verify(); receipt layer must catch it")
        else:
            t("SAFE.del.%s" % label, not okv and ("mismatch" in whyv or "corrupt-file" in whyv),
              "ok=%s why=%s" % (okv, whyv))
    # genesis/prefix deletion vs HELD receipts: PR9 close-hash tie catches it
    c, root = make_chain()
    rec = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
    del c.events[0]          # M06 loan
    del c.events[0]          # M06 close (now head)
    okv, _, whyv = c.verify()
    okr, det = verify_receipt(c, rec)
    t("SAFE.del.prefix M06 deletion detected (anchor + close-hash)", not okr,
      "verify=%s why=%s | receipt=%s" % (okv, whyv, det))
    # append after close: verify() OK, receipt layer catches
    c, root = make_chain()
    c.add_event(None, "contribution", "Ghost", 1, T)
    okv, _, whyv = c.verify()
    t("chain.append.001 verify() stays OK after post-close append", okv,
      "chain math is consistent; only receipt terminality sees it")
    # insert in middle with rewritten links (attacker+recompute) -> covered in recompute group

    # ---------- full recompute (attacker with file control) ----------
    c, root = make_chain()
    c.events[6]["amount_paise"] = 1
    full_recompute(c)
    okv, _, whyv = c.verify()
    t("chain.recompute.001 consistent recompute passes verify()", okv,
      "verify() checks internal consistency; a consistent rewrite is the documented boundary")
    t("chain.recompute.002 recompute leaves roots metadata stale", root["root_hash"] != c.events[-1]["hash"],
      "root metadata still points at the OLD tail hash until the attacker updates it")
    # PR9 close-hash tie: receipt root MUST equal recomputed close hash
    rec = receipt_payload("G-RAJ-042", "M07", root, "Sita", chain=c)
    okr, det = verify_receipt(c, rec)
    t("SAFE.recompute.003 full recompute caught by close-hash tie (PR9)", not okr,
      "receipt=%s" % det)
    # recompute AND update root metadata
    c2, root2 = make_chain()
    c2.events[6]["amount_paise"] = 1
    full_recompute(c2)
    c2.roots["M07"]["root_hash"] = c2.events[-1]["hash"]
    okr2, det2 = verify_receipt(c2, receipt_payload("G-RAJ-042", "M07", root2, "Sita", chain=c2))
    t("SAFE.recompute.004 recompute + metadata update caught (close-hash + member binding)", not okr2,
      "receipt=%s" % det2)
    # recompute + root update + append post-close... still caught by terminality
    c3, root3 = make_chain()
    c3.events[6]["amount_paise"] = 1
    full_recompute(c3)
    c3.roots["M07"]["root_hash"] = c3.events[-1]["hash"]
    c3.add_event(None, "contribution", "Ghost", 50000, T)
    okr3, det3 = verify_receipt(c3, receipt_payload("G-RAJ-042", "M07", root3, "Sita", chain=c3))
    t("SAFE.recompute.005 receipt catches recompute + append ghost event", not okr3 and ("events-after-close" in det3 or "FORK" in det3), det3)
    # cross-group event smuggling: per-event group now hashed + checked (PR10)
    c4, root4 = make_chain()
    c4.events[0]["group"] = "G-OTHER-CLAN"
    full_recompute(c4)
    okv4, _, why4 = c4.verify()
    okr4, det4 = verify_receipt(c4, receipt_payload("G-RAJ-042", "M07", root4, "Sita", chain=c4))
    t("SAFE.recompute.006 cross-group smuggling caught (group hashed, PR10)", not okv4 or not okr4,
      "verify=%s why=%s | receipt=%s" % (okv4, why4, det4))

    # ---------- roots tampering ----------
    c, root = make_chain()
    rec = receipt_payload("G-RAJ-042", "M07", root, "Sita")   # member holds the ORIGINAL root FIRST
    okv, _, _ = c.verify()
    c.roots["M07"]["root_hash"] = "f" * 64
    okv2, _, why2 = c.verify()
    t("VULN.roots.001 chain.verify() blind to roots metadata", okv and okv2,
      "verify() never recomputes/checks roots; tampered meeting root passes chain verify")
    okr, det = verify_receipt(c, rec)
    t("SAFE.roots.002 receipt layer catches root tamper (receipt built before tamper)", not okr and "FORK" in det, det)
    # roots missing root_hash entirely -> KeyError crash in verify_receipt
    c5, root5 = make_chain()
    c5.roots["M07"] = {"ts": T}
    try:
        verify_receipt(c5, receipt_payload("G-RAJ-042", "M07", root5, "Sita"))
        t("VULN.roots.003 partial root metadata crashes verify_receipt", False, "no exception raised")
    except KeyError as e:
        t("VULN.roots.003 partial root metadata crashes verify_receipt", True,
          "KeyError %r: violates 'never crashes / corrupt input = fail with detail'" % (e,))
    except Exception as e:
        t("VULN.roots.003 partial root metadata crashes verify_receipt", True, "%s: %r" % (type(e).__name__, e))
    # roots value None
    c6, root6 = make_chain()
    c6.roots["M07"] = None
    okr6, det6 = verify_receipt(c6, receipt_payload("G-RAJ-042", "M07", root6, "Sita"))
    t("chain.roots.004 None root metadata -> meeting-root-missing (graceful)", not okr6 and "meeting-root-missing" in det6, det6)
    # duplicate close of same meeting id now RAISES (PR10 A05)
    c7, root7 = make_chain()
    old_hash = root7["root_hash"]
    try:
        r_b = c7.close_meeting("M07", T)
        t("SAFE.roots.005 close_meeting same id REJECTED (PR10)", False, "dup close accepted")
    except ValueError:
        t("SAFE.roots.005 close_meeting same id REJECTED (PR10)", True)
    t("chain.roots.006 original root intact", c7.roots["M07"]["root_hash"] == old_hash)

    # ---------- group binding ----------
    c, root = make_chain()
    try:
        okr, det = verify_receipt(c, receipt_payload("G-OTHER", "M07", root, "Sita"))
        t("SAFE.group.001 wrong group receipt fails", not okr and "group-mismatch" in det, det)
    except Exception as e:
        t("SAFE.group.001 wrong group receipt fails", False, repr(e))
    c8 = BahiChain("")
    try:
        c8.add_event(1, "contribution", "Sita", 100, T)
        t("SAFE.group.002 empty group id REJECTED (PR10)", False, "empty group accepted")
    except ValueError:
        t("SAFE.group.002 empty group id REJECTED (PR10)", True)

    # ---------- determinism ----------
    cA, rA = make_chain()
    cB, rB = make_chain()
    t("chain.det.001 identical chains identical hashes", [e["hash"] for e in cA.events] == [e["hash"] for e in cB.events])
    hA = h(1, "contribution", "Sita", 100, T)
    hB = h(1, "contribution", "Sita", 100, T)
    t("chain.det.002 h() deterministic", hA == hB)
    t("chain.det.003 same input different group differs", h("GENESIS", "A") != h("GENESIS", "B"))

    # ---------- load/save robustness ----------
    d = tempfile.mkdtemp(prefix="bahi-attack-")
    path = os.path.join(d, "chain.json")
    c9, _ = make_chain()
    c9.save(path)
    t("chain.save.001 atomic save writes file", os.path.exists(path))
    t("chain.save.002 .bak copy written", os.path.exists(path + ".bak"))
    c10 = BahiChain.load(path)
    t("chain.save.003 load roundtrip identical export", c10.export() == c9.export())
    t("chain.save.004 .bak content identical", open(path + ".bak").read() == open(path).read())
    # .bak failure is best-effort: make .bak path a directory (after first save)
    p2 = os.path.join(d, "chain2.json")
    c9.save(p2)
    os.unlink(p2 + ".bak")
    os.mkdir(p2 + ".bak")
    try:
        c9.save(p2)
        t("chain.save.005 save survives .bak write failure", True)
    except Exception as e:
        t("chain.save.005 save survives .bak write failure", False, repr(e))
    shutil_rm = lambda *a, **k: None
    import shutil
    shutil.rmtree(d)

    for label, bad in (
        ("missing-file", os.path.join(tempfile.mkdtemp(), "nope.json")),
        ("invalid-json", "[not json"),
        ("json-array", "[1,2,3]"),
        ("dict-no-events", '{"group": "G"}'),
        ("events-not-list", '{"group": "G", "events": {"a":1}}'),
        ("group-int", '{"group": 123, "events": []}'),
        ("group-empty", '{"group": "", "events": []}'),
    ):
        fp = tempfile.mktemp(suffix=".json")
        if label == "missing-file":
            pass
        elif label == "invalid-json":
            with open(fp, "w") as f: f.write(bad)
        elif label == "json-array":
            with open(fp, "w") as f: f.write(bad)
        elif label == "dict-no-events":
            with open(fp, "w") as f: f.write(bad)
        elif label == "events-not-list":
            with open(fp, "w") as f: f.write(bad)
        elif label == "group-int":
            with open(fp, "w") as f: f.write(bad)
        elif label == "group-empty":
            with open(fp, "w") as f: f.write(bad)
        try:
            cc = BahiChain.load(fp)
            t("SAFE.load.%s no crash + corrupt flag" % label, cc.corrupt, "corrupt=%s" % cc.corrupt)
        except Exception as e:
            t("SAFE.load.%s no crash + corrupt flag" % label, False, "%s: %r" % (type(e).__name__, e))
        try:
            os.unlink(fp)
        except OSError:
            pass
    # deep JSON nesting bomb -> RecursionError escapes load()
    deep = "[" * 100000 + "1" + "]" * 100000
    fp = tempfile.mktemp(suffix=".json")
    with open(fp, "w") as f: f.write(deep)
    try:
        BahiChain.load(fp)
        t("VULN.load.deep-nesting RecursionError crash", False, "no exception")
    except RecursionError:
        t("VULN.load.deep-nesting RecursionError crash", True, "json.loads hits recursion limit; load() only catches OSError/ValueError -> CRASH")
    except Exception as e:
        t("VULN.load.deep-nesting RecursionError crash", True, "%s: %r" % (type(e).__name__, e))
    os.unlink(fp)
    # events element not a dict: verify() crashes instead of graceful
    fp = tempfile.mktemp(suffix=".json")
    with open(fp, "w") as f:
        json.dump({"group": "G", "events": [1, 2, 3], "roots": {}}, f)
    cc = BahiChain.load(fp)
    try:
        okv, _, whyv = cc.verify()
        t("VULN.load.events-not-dict verify() crashes", False,
          "returned %s/%s: expected crash: 'field not in ev' on an int raises TypeError" % (okv, whyv))
    except TypeError as e:
        t("VULN.load.events-not-dict verify() crashes", True,
          "TypeError %r: verify() promises 'NEVER raises on malformed data' but crashes on non-dict event rows" % (e,))
    except Exception as e:
        t("VULN.load.events-not-dict verify() crashes", True, "%s: %r" % (type(e).__name__, e))
    os.unlink(fp)

    return R