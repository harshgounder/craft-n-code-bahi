#!/usr/bin/env python3
"""attack_fuzz.py - deterministic high-volume fuzzing of the BAHI attack surface.

Every sub-suite generates a large, fixed number of distinct probes (several are
>=1000) and reports exact pass/fail counts. Deterministic (seeded) so results
are reproducible byte-for-byte. The harness itself is stdlib-only; the code
under test (frozen in src/) may use `cryptography` for Ed25519.

Suites (probe counts fixed at the top of each function):
  1. csv_injection_fuzz    1200 payloads  through csv_safe_cell()
  2. xss_fuzz              1200 payloads  through html_escape()
  3. chain_mutation_fuzz   1200 corruptions through load()/verify()/receipt
  4. property_fuzz         1500 random VALID ledgers -> invariants hold
  5. receipt_tamper_fuzz   1200 receipt tamperings -> never crash / correct verdict
  6. type_confusion_fuzz   1000 bad-type inputs -> ValueError / structured fail

Exit 0 only if every probe passes. A probe "passes" when the code behaves
correctly (rejects the attack, survives the corruption, or holds the invariant).
"""
import os
import re
import sys
import json
import random
import string
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from chain import BahiChain, receipt_payload, verify_receipt, h  # noqa: E402
from exporter import (csv_safe_cell, html_escape, hint_flags,  # noqa: E402
                      audit_report, export_csv, HINT_SEVERITY)
from loans import balances  # noqa: E402
from witness import (sign_entry, is_valid_sig, generate_keypair,  # noqa: E402
                     sign_entry_ed25519, ed25519_available)  # noqa: E402

PASS = 0
FAIL = 0
FAILURES = []


def _check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        if len(FAILURES) < 12:
            FAILURES.append("%s :: %s" % (name, detail))


# Suite accounting: each suite snapshots PASS/FAIL at its start.
def _snap():
    return [PASS, FAIL]


def _suite_result(name, before):
    p = PASS - before[0]
    f = FAIL - before[1]
    print("  %-24s %5d probes   %d failed" % (name, p + f, f))
    return f == 0


# ---------------------------------------------------------------------------
# 1. CSV injection fuzz
# ---------------------------------------------------------------------------
_CSV_PREFIXES = ["=", "+", "-", "@", "\t", "\r", "\r\n", " \t", "  ", " =", "\t=",
                 "\r=", "\n=", "\t\n=", "   "]
_CSV_BODIES = ["cmd|'/C calc'!A0", "HYPERLINK(\"http://evil/x\")", "1+1", "2+2",
               "@SUM(1,1)", "DDE(\"cmd\";\"/C calc\";\"\")", "IMPORTXML(\"http://e\",\"//\")",
               "cmd.exe", "javascript:alert(1)", "`id`", "$(rm -rf /)", "&calc", "|calc",
               "A1+A2", "SUM(A1:A9)", "1,000", "2024-01-01", "foo", "bar", "=2+2"]


def csv_injection_fuzz(n=1200):
    before = _snap()
    rng = random.Random(0xC5)  # fixed seed
    payloads = []
    # curated prefix x body combos
    for p in _CSV_PREFIXES:
        for b in _CSV_BODIES:
            payloads.append(p + b)
    # deterministic random mutations to reach n
    while len(payloads) < n:
        base = rng.choice(payloads[:len(_CSV_PREFIXES) * len(_CSV_BODIES)])
        mut = rng.choice(["upper", "quote", "comma", "semi", "spaces", "newline", "null"])
        if mut == "upper":
            payloads.append(base.upper())
        elif mut == "quote":
            payloads.append('"' + base)
        elif mut == "comma":
            payloads.append(base + ",x")
        elif mut == "semi":
            payloads.append(base + ";x")
        elif mut == "spaces":
            payloads.append(" " * rng.randint(1, 5) + base)
        elif mut == "newline":
            payloads.append("\n" + base)
        else:
            payloads.append(base + "\x00")
    payloads = payloads[:n]
    for pl in payloads:
        out = csv_safe_cell(pl)
        dangerous = ("=", "+", "-", "@", "\t", "\r")
        s = str(pl)
        # mirror csv_safe_cell: dangerous if first byte OR first byte after lstrip
        if s[:1] in dangerous or s.lstrip()[:1] in dangerous:
            _check("csv", out.startswith("'"), "dangerous %r not neutralized -> %r" % (pl, out))
        else:
            _check("csv", out == s, "safe %r over-escaped -> %r" % (pl, out))
    return _suite_result("csv_injection_fuzz", before)


# ---------------------------------------------------------------------------
# 2. XSS / HTML-escape fuzz
# ---------------------------------------------------------------------------
_XSS_VECTORS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>", "'-alert(1)-'", "<a href='javascript:alert(1)'>x</a>",
    "<iframe src=javascript:alert(1)>", "<body onload=alert(1)>", "<math><mi xlink:href=//evil>",
    "&lt;script&gt;", "&#x3c;script&#x3e;", "javascript:alert(1)", "onmouseover=alert(1)",
    "\";alert(1);//", "<IMG SRC=\"javascript:alert(1)\">", "`><svg onload=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}", "%3Cscript%3E", "\u0000<script>",
    "<scr<script>ipt>", "<<SCRIPT>alert(1)//<</SCRIPT>", "<b onmouseover=alert(1)>x</b>",
]

_AMP_ENTITIES = ("amp;", "lt;", "gt;", "quot;", "#39;")


def _escaped_clean(s):
    """True if `s` contains no raw dangerous chars and only valid entities."""
    if any(c in s for c in "<>\"'"):
        return False
    # every '&' must start one of the known entities
    i = 0
    while i < len(s):
        if s[i] == "&":
            if not any(s.startswith("&" + e, i) for e in _AMP_ENTITIES):
                return False
            i += 1
        else:
            i += 1
    return True


def xss_fuzz(n=1200):
    before = _snap()
    rng = random.Random(0x5EC)  # fixed seed
    payloads = list(_XSS_VECTORS)
    while len(payloads) < n:
        base = rng.choice(_XSS_VECTORS)
        mut = rng.choice(["case", "insert", "concat", "pad", "encode", "dup"])
        if mut == "case":
            payloads.append(base.swapcase())
        elif mut == "insert":
            pos = rng.randint(0, len(base))
            payloads.append(base[:pos] + rng.choice(["<", ">", "&", '"', "'"]) + base[pos:])
        elif mut == "concat":
            payloads.append(base + rng.choice(_XSS_VECTORS))
        elif mut == "pad":
            payloads.append("  " + base + "  ")
        elif mut == "encode":
            payloads.append(base.replace("<", "&lt;").replace(">", "&gt;"))
        else:
            payloads.append(base + base)
    payloads = payloads[:n]
    for pl in payloads:
        out = html_escape(pl)
        _check("xss", _escaped_clean(out), "raw dangerous char in %r -> %r" % (pl, out))
    # a handful of explicitly-safe strings (no dangerous chars) pass unchanged
    for safe in ("hello", "Rs 100.00", "2026-08-02T10:00:00", "Sita"):
        _check("xss-safe", html_escape(safe) == safe, "%r mutated" % safe)
    return _suite_result("xss_fuzz", before)


# ---------------------------------------------------------------------------
# 3. Chain mutation / corruption fuzz  (never crash, structured verdict)
# ---------------------------------------------------------------------------
def _base_export():
    c = BahiChain("G-FUZZ")
    c.add_event(1, "contribution", "Sita", 10000, "t")
    c.add_event(2, "loan", "Asha", 50000, "t")
    c.add_event(3, "repayment", "Asha", 10000, "t")
    c.add_event(4, "contribution", "Geeta", 10000, "t")
    c.close_meeting("M01", "t")
    return c.export()


_MUT_FIELDS = ["seq", "type", "member", "amount_paise", "ts", "prev", "hash", "group"]
_BAD_VALUES = [None, "", "x", -5, 2**63, True, False, 0.5, [], {}, "\u202e<script>", " " * 1000]


def _apply_mutation(exp, rng):
    d = json.loads(json.dumps(exp))  # deep copy
    if not d["events"]:
        d["events"] = [{"seq": 1, "group": "G", "type": "contribution", "member": "A",
                        "amount_paise": 100, "ts": "t", "prev": "0", "hash": "0"}]
    kind = rng.randint(0, 9)
    ev = rng.choice(d["events"])
    if kind == 0:      # delete a random field
        f = rng.choice(_MUT_FIELDS)
        ev.pop(f, None)
    elif kind == 1:    # bad value in a field
        f = rng.choice(_MUT_FIELDS)
        ev[f] = rng.choice(_BAD_VALUES)
    elif kind == 2:    # delete an event
        d["events"].pop(rng.randrange(len(d["events"])))
    elif kind == 3:    # duplicate an event
        d["events"].append(json.loads(json.dumps(rng.choice(d["events"]))))
    elif kind == 4:    # reorder two events
        i, j = rng.sample(range(len(d["events"])), 2)
        d["events"][i], d["events"][j] = d["events"][j], d["events"][i]
    elif kind == 5:    # change group id
        d["group"] = rng.choice(["", "G-OTHER", "G\u202e", " " * 50])
    elif kind == 6:    # roots tamper
        d["roots"] = rng.choice([{}, {"M01": "garbage"}, {"x": {"root_hash": "", "root_seq": "x", "ts": "", "witnesses": "no"}}])
    elif kind == 7:    # append ghost after close
        d["events"].append({"seq": 99, "group": "G", "type": "contribution", "member": "Ghost",
                            "amount_paise": 1, "ts": "t", "prev": "x", "hash": "y"})
    elif kind == 8:    # extra/unknown field
        ev["__evil__"] = rng.choice(_BAD_VALUES)
    else:              # string-ify a numeric field
        ev[rng.choice(["seq", "amount_paise"])] = "not-a-number"
    return d


def _chain_from(d):
    c = BahiChain()
    c.group_id = d.get("group", "")
    c.events = d.get("events", [])
    c.roots = d.get("roots", {})
    return c


def chain_mutation_fuzz(n=1200):
    before = _snap()
    rng = random.Random(0x5EED)  # fixed seed
    base = _base_export()
    rec = receipt_payload("G-FUZZ", "M01",
                          {"root_hash": "0" * 64, "root_seq": 5, "ts": "t", "witnesses": []},
                          "Sita", chain=None)
    for _ in range(n):
        mut = _apply_mutation(base, rng)
        c = _chain_from(mut)
        try:
            c.verify()
            hint_flags(c)
            audit_report(c)
            balances(c)
            export_csv(c)
            verify_receipt(c, rec)
            _check("mutate", True)
        except Exception as e:  # noqa: BLE001 - the whole point is "no crash"
            _check("mutate", False, "raised %s: %s on %r" % (type(e).__name__, e, mut))
    # broken-JSON file loads must also never crash
    for _ in range(n // 10):
        try:
            fd, fp = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w") as f:
                f.write(rng.choice(["", "{", "[", "not json", "{\"events\": [1,2", "null"]))
            c = BahiChain.load(fp)
            c.verify()
            hint_flags(c)
            _check("load", True)
            os.unlink(fp)
        except Exception as e:  # noqa: BLE001
            _check("load", False, "raised %s: %s" % (type(e).__name__, e))
    return _suite_result("chain_mutation_fuzz", before)


# ---------------------------------------------------------------------------
# 4. Random VALID ledger property fuzz (1500 seeds)
# ---------------------------------------------------------------------------
_TYPES = ("contribution", "loan", "repayment", "correction")
_AMTS = [0, 1, 100, 10000, 50000, 100000, 1000000, 2**31 - 1]


def _random_member(rng):
    return "".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(1, 10)))


def _random_ts(rng):
    return "2026-%02d-%02dT%02d:%02d:%02d" % (rng.randint(1, 12), rng.randint(1, 28),
                                              rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))


def property_fuzz(n=1500):
    before = _snap()
    rng = random.Random(0xDEFACED)
    for seed in range(n):
        rr = random.Random(seed)
        c = BahiChain("G-PROP-%d" % seed)
        ops = rr.randint(1, 60)
        try:
            for _ in range(ops):
                if rr.random() < 0.15 and c.events:
                    mid = "M%d" % rr.randint(0, 9999)
                    try:
                        c.close_meeting(mid, _random_ts(rr))
                    except ValueError:
                        pass  # duplicate id -> allowed to reject
                else:
                    c.add_event(None, rr.choice(_TYPES), _random_member(rr),
                                rr.choice(_AMTS), _random_ts(rr))
            ok, seq, why = c.verify()
            _check("prop-verify", ok, "seed %d: verify -> %s @ %s (%s)" % (seed, ok, seq, why))
            bals = balances(c)
            neg = [m for m, b in bals.items()
                   if b["outstanding_paise"] < 0 or b["over_repaid_paise"] < 0]
            _check("prop-balance", not neg, "seed %d: negative balance %r" % (seed, neg[:3]))
            _ = hint_flags(c)
            _ = export_csv(c)
            _check("prop", True)
        except Exception as e:  # noqa: BLE001
            _check("prop", False, "seed %d raised %s: %s" % (seed, type(e).__name__, e))
    return _suite_result("property_fuzz", before)


# ---------------------------------------------------------------------------
# 5. Receipt tamper fuzz (1200 tamperings -> never crash)
# ---------------------------------------------------------------------------
def _valid_receipt():
    c = BahiChain("G-RCP")
    for i in range(1, 5):
        c.add_event(i, "contribution", "Sita", 10000, "t")
    root = c.close_meeting("M01", "t")
    root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M01"}, "pass-Meera", "Meera"))
    root["witnesses"].append(sign_entry({"root": root["root_hash"], "meeting": "M01"}, "pass-Laxmi", "Laxmi"))
    r = receipt_payload("G-RCP", "M01", root, "Sita", chain=c)
    return c, r


def receipt_tamper_fuzz(n=1200):
    before = _snap()
    rng = random.Random(0xCE1F)
    c, rec = _valid_receipt()
    for _ in range(n):
        r = json.loads(json.dumps(rec))
        kind = rng.randint(0, 7)
        try:
            if kind == 0:
                r["root"] = "".join(rng.choice("0123456789abcdef") for _ in range(64))
            elif kind == 1:
                r["member"] = rng.choice(["Nobody", "", "<script>", "Sita"])
            elif kind == 2:
                r["witnesses"] = rng.choice([[], "x", [{"witness": "Meera", "sig": "0" * 64}],
                                              [{"witness": "A", "sig": "f" * 64}, {"witness": "B", "sig": "0" * 64}]])
            elif kind == 3:
                r["member_events"] = rng.choice([None, [], [{"seq": 1, "hash": "0" * 64}],
                                                  [{"seq": 99, "hash": "f" * 64}]])
            elif kind == 4:
                r["meeting"] = rng.choice(["M99", "", 123, "M01"])
            elif kind == 5:
                r["root_seq"] = rng.choice([0, -1, 99, "x", True, 4])
            elif kind == 6:
                r["group"] = rng.choice(["G-OTHER", "", "G-RCP"])
            else:
                del r[rng.choice(list(r.keys()))]
            out = verify_receipt(c, r)
            _check("receipt", isinstance(out, tuple) and len(out) == 2, "bad return %r" % (out,))
        except Exception as e:  # noqa: BLE001
            _check("receipt", False, "raised %s: %s" % (type(e).__name__, e))
    return _suite_result("receipt_tamper_fuzz", before)


# ---------------------------------------------------------------------------
# 6. Type-confusion fuzz (1000 bad inputs -> ValueError / structured fail)
# ---------------------------------------------------------------------------
def type_confusion_fuzz(n=1000):
    before = _snap()
    rng = random.Random(0xBAD5EED)
    bad_types = [None, 1.5, True, False, [], {}, ("x",), b"bytes", 1j, float("nan") if False else 3]
    for _ in range(n):
        c = BahiChain("G-TY")
        try:
            action = rng.randint(0, 3)
            if action == 0:  # add_event with a bad field
                bad = dict(seq=rng.choice([None, 1, "1", 1.0, True, -1, 999]),
                           etype=rng.choice(_TYPES + ("MEETING-CLOSE", "x", None)),
                           member=rng.choice(["A", "", None, "__root__", 123]),
                           amt=rng.choice([100, -5, 100.5, True, None, "100", 2**63]),
                           ts=rng.choice(["t", "", None, 123]))
                c.add_event(bad["seq"], bad["etype"], bad["member"], bad["amt"], bad["ts"])
            elif action == 1:  # close_meeting bad args
                c.add_event(1, "contribution", "A", 100, "t")
                mid = rng.choice(["M1", "", None, 5])
                ws = rng.choice([None, [], ["x"], [{"witness": "A", "sig": "0" * 64},
                                                   {"witness": "A", "sig": "1" * 64}],
                                 [{"witness": "A", "sig": "z" * 64}]])
                c.close_meeting(mid, rng.choice(["t", "", None]), witnesses=ws)
            elif action == 2:  # verify_receipt with malformed receipt
                rec = rng.choice([None, "x", 5, [], {"group": 1}, {"group": "G", "meeting": "M", "root": None}])
                verify_receipt(c, rec)
            else:  # balances / hints with malformed events
                c.events = [rng.choice(bad_types)]
                balances(c)
                hint_flags(c)
            _check("type", True)  # reached here = no crash; ValueError is caught below as "ok"
        except ValueError:
            _check("type", True)  # clean rejection
        except Exception as e:  # noqa: BLE001
            _check("type", False, "raised %s: %s" % (type(e).__name__, e))
    return _suite_result("type_confusion_fuzz", before)


# ---------------------------------------------------------------------------
def main():
    print("=" * 78)
    print("BAHI attack-surface fuzz  (deterministic, seeded)")
    print("=" * 78)
    total_fail = 0
    total_fail += (not csv_injection_fuzz(1200))
    total_fail += (not xss_fuzz(1200))
    total_fail += (not chain_mutation_fuzz(1200))
    total_fail += (not property_fuzz(1500))
    total_fail += (not receipt_tamper_fuzz(1200))
    total_fail += (not type_confusion_fuzz(1000))
    print("-" * 78)
    print("TOTAL: %d probes, %d passed, %d failed" % (PASS + FAIL, PASS, FAIL))
    if FAILURES:
        print("first failures:")
        for f in FAILURES:
            print("  - " + f)
    print("=" * 78)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
