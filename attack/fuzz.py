#!/usr/bin/env python3
"""fuzz.py - property-based randomized attack testing against chain.py,
witness.py, loans.py, exporter.py. Seeded RNG for reproducibility.
Usage: python3 fuzz.py [iterations] [seed]
"""
import hashlib, json, random, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chain import BahiChain, receipt_payload, verify_receipt, h
from witness import sign, verify
from loans import balances
from exporter import hint_flags

ITERS = int(sys.argv[1]) if len(sys.argv) > 1 else 100
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 0xB4A11
rng = random.Random(SEED)

MEMBERS = ["Sita", "Geeta", "Reema", "Kavita", "Asha", "Meera", "Laxmi", "Rani", "Sunita", "Pooja"]
TYPES = ["contribution", "loan", "repayment", "correction"]

def random_chain(max_events=40, meetings=3, group="G-FUZZ"):
    c = BahiChain(group)
    mid = 1
    for i in range(1, max_events + 1):
        if meetings and rng.random() < 0.08:  # occasional meeting close
            r = c.close_meeting("M%02d" % mid, "2026-08-%02dT10:00:00" % (mid % 28 + 1))
            for w in rng.sample(MEMBERS, 2):
                pass_words = "pass-" + w
                r["witnesses"].append(sign({"root": r["root_hash"], "meeting": "M%02d" % mid}, pass_words, w))
            mid += 1
            meetings -= 1
            if meetings == 0:
                break            # chain must END at a meeting close for honest receipts
            continue
        c.add_event(i, rng.choice(TYPES), rng.choice(MEMBERS),
                    rng.choice([0, 1, 100, 500, 1000, 10000, 50000, 999999999]),
                    "2026-08-%02dT10:%02d:%02d" % (rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59)))
    if meetings and (not c.events or c.events[-1]["type"] != "MEETING-CLOSE"):
        r = c.close_meeting("M%02d" % mid, "2026-08-28T10:00:00")
        for w in rng.sample(MEMBERS, 2):
            r["witnesses"].append(sign({"root": r["root_hash"], "meeting": "M%02d" % mid}, "pass-" + w, w))
    return c

def full_recompute(c):
    prev = h("GENESIS", c.group_id)
    for ev in c.events:
        ev["prev"] = prev
        ev["hash"] = h(prev, ev["seq"], ev["type"], ev["member"], ev["amount_paise"], ev["ts"])
        prev = ev["hash"]

def run():
    R = []
    def t(tid, ok, detail=""):
        R.append((tid, bool(ok), detail))

    # P1: honest random chains always verify OK
    for i in range(ITERS):
        c = random_chain()
        ok, _, why = c.verify()
        t("fuzz.P1.%04d honest chain verifies" % i, ok, "why=%s" % why)
    # P2: full recompute preserves chain validity (attacker-consistent chain)
    for i in range(ITERS):
        c = random_chain()
        c.events[rng.randrange(len(c.events))]["amount_paise"] = rng.randint(0, 10**9)
        full_recompute(c)
        ok, _, why = c.verify()
        t("fuzz.P2.%04d recompute-consistent chain passes verify()" % i, ok, "why=%s" % why)
    # P3: naive single-field tamper always breaks verify (except group, not in hash)
    for i in range(ITERS):
        c = random_chain()
        if len(c.events) < 2:
            c = random_chain()
        idx = rng.randrange(len(c.events))
        field = rng.choice(["amount_paise", "member", "type", "ts", "seq", "prev", "hash", "group"])
        c.events[idx][field] = "TAMPER-%d" % i
        ok, bad_seq, why = c.verify()
        if field == "group":
            t("fuzz.P3.%04d tamper group@%d UNDETECTED (group not hashed)" % (i, idx), ok,
              "why=%s: group field is excluded from the per-event hash -> tamper passes verify()" % why)
        else:
            t("fuzz.P3.%04d tamper %s@%d detected" % (i, field, idx), not ok, "why=%s" % why)
    # P4a: bound receipt catches edit+recompute of the MEMBER'S OWN events (PR4 fix verified)
    for i in range(ITERS):
        c = random_chain()
        if not c.roots:
            c = random_chain()
        mid = sorted(c.roots)[-1]
        rs = c.roots[mid]["root_seq"]
        pool = [e["member"] for e in c.events if e.get("type") != "MEETING-CLOSE" and e.get("seq", 0) <= rs]
        if not pool:
            continue
        member = rng.choice(pool)
        rec = receipt_payload(c.group_id, mid, c.roots[mid], member, c)
        own = [i for i, e in enumerate(c.events) if e.get("member") == member and e.get("type") != "MEETING-CLOSE"]
        if not own:
            continue
        c.events[rng.choice(own)]["amount_paise"] = rng.randint(1, 10**6)
        full_recompute(c)
        ok, det = verify_receipt(c, rec)
        t("fuzz.P4a.%04d bound receipt catches OWN-event edit+recompute (PR4 FIX verified)" % i, not ok, "det=%s" % det)
    # P4d: edit+recompute of a NON-member event AFTER the member's last event -> MATCH (binding blind spot)
    for i in range(ITERS):
        c = random_chain()
        if not c.roots:
            c = random_chain()
        mid = sorted(c.roots)[-1]
        rs = c.roots[mid]["root_seq"]
        pool = [e["member"] for e in c.events if e.get("type") != "MEETING-CLOSE" and e.get("seq", 0) <= rs]
        if not pool:
            continue
        member = rng.choice(pool)
        rec = receipt_payload(c.group_id, mid, c.roots[mid], member, c)
        own_seqs = {e["seq"] for e in c.events if e.get("member") == member and e.get("type") != "MEETING-CLOSE"}
        last_own = max(own_seqs) if own_seqs else None
        targets = [i for i, e in enumerate(c.events)
                   if e.get("type") != "MEETING-CLOSE" and e.get("member") != member
                   and e.get("seq", 0) > (last_own or 0) and e.get("seq", 0) <= rs]
        if not targets:
            continue
        c.events[rng.choice(targets)]["amount_paise"] = rng.randint(1, 10**6)
        full_recompute(c)
        ok, det = verify_receipt(c, rec)
        t("fuzz.P4d.%04d NON-member event after member's last event edited+recomputed -> receipt MATCHes (blind spot)" % i,
          ok and det == "MATCH",
          "det=%s: other members' line items between the holder's last event and the close are NOT covered by her receipt; edit them + rehash -> entire meeting's other rows forged while her receipt MATCHes" % det)
    # P4c: mutating the MEETING-CLOSE event itself + recompute -> still MATCH (root pins metadata, not the close)
    for i in range(ITERS):
        c = random_chain()
        if not c.roots:
            c = random_chain()
        mid = sorted(c.roots)[-1]
        rs = c.roots[mid]["root_seq"]
        pool = [e["member"] for e in c.events if e.get("type") != "MEETING-CLOSE" and e.get("seq", 0) <= rs]
        if not pool:
            continue
        rec = receipt_payload(c.group_id, mid, c.roots[mid], rng.choice(pool), c)
        close_idx = [i for i, e in enumerate(c.events) if e.get("type") == "MEETING-CLOSE" and e.get("seq") == rs]
        if not close_idx:
            continue
        c.events[close_idx[0]]["ts"] = "1970-01-01T00:00:00"
        full_recompute(c)
        ok, det = verify_receipt(c, rec)
        t("fuzz.P4c.%04d close-event edit + recompute -> bound receipt MATCHes (root pin hole)" % i,
          ok and det == "MATCH",
          "det=%s: the receipt root equals STALE metadata; the actual close event's recomputed hash is never compared. Editing the close itself (ts/amount) stays silent" % det)
    # P4b: LEGACY receipts (no member_events) still MATCH under recompute
    for i in range(ITERS):
        c = random_chain()
        if not c.roots:
            c = random_chain()
        mid = sorted(c.roots)[-1]
        rs = c.roots[mid]["root_seq"]
        pool = [e["member"] for e in c.events if e.get("type") != "MEETING-CLOSE" and e.get("seq", 0) <= rs]
        if not pool:
            continue
        rec = receipt_payload(c.group_id, mid, c.roots[mid], rng.choice(pool))   # no chain -> legacy
        if c.events:
            c.events[rng.randrange(len(c.events))]["amount_paise"] = rng.randint(1, 10**6)
        full_recompute(c)
        ok, det = verify_receipt(c, rec)
        t("fuzz.P4b.%04d legacy receipt still MATCHes under recompute (finding persists)" % i, ok and det == "MATCH",
          "det=%s: receipt without member_events falls back to member-exists; recompute hole open for all pre-PR4 receipts" % det)
    # P5: honest bound receipt for an EXISTING member always MATCHes (LAST meeting)
    for i in range(ITERS):
        c = random_chain()
        if not c.roots:
            c = random_chain()
        mid = sorted(c.roots)[-1]
        rs = c.roots[mid]["root_seq"]
        pool = [e["member"] for e in c.events if e.get("type") != "MEETING-CLOSE" and e.get("seq", 0) <= rs]
        if not pool:
            continue
        rec = receipt_payload(c.group_id, mid, c.roots[mid], rng.choice(pool), c)
        ok, det = verify_receipt(c, rec)
        t("fuzz.P5.%04d honest bound receipt MATCH" % i, ok and det == "MATCH", "det=%s" % det)
    # P6: balances invariant loaned - repaid == outstanding (int math, arbitrary values)
    for i in range(ITERS):
        c = random_chain()
        b = balances(c)
        bad = [m for m, v in b.items() if v["loaned_paise"] - v["repaid_paise"] != v["outstanding_paise"]]
        t("fuzz.P6.%04d balance invariant" % i, not bad, "bad=%s" % bad)
    # P7: export -> load roundtrip byte-identical
    for i in range(ITERS):
        c = random_chain()
        d = c.export()
        c2 = BahiChain()
        c2.group_id = d["group"]; c2.events = d["events"]; c2.roots = d["roots"]
        t("fuzz.P7.%04d export/load roundtrip equal" % i, c2.export() == d)
    # P8: witness sign/verify roundtrip on random payloads
    for i in range(ITERS):
        p = {"root": hashlib.sha256(str(rng.random()).encode()).hexdigest(),
             "meeting": "M%02d" % rng.randint(1, 30),
             "n": rng.randint(0, 10**9)}
        w = rng.choice(MEMBERS)
        s = sign(p, "pass-" + w, w)
        t("fuzz.P8.%04d witness roundtrip" % i, verify(p, s, "pass-" + w, w))
    # P9: hint_flags never crashes on random chains (incl. corrupt)
    for i in range(ITERS // 2):
        c = random_chain()
        if i % 3 == 0:
            c.roots["__corrupt__"] = {"corrupt": "x"}
        try:
            fl = hint_flags(c)
            t("fuzz.P9.%04d hint_flags no crash" % i, isinstance(fl, list))
        except Exception as e:
            t("fuzz.P9.%04d hint_flags no crash" % i, False, "%s: %r" % (type(e).__name__, e))
    # P10: verify_receipt never crashes on random malformed receipts
    for i in range(ITERS):
        c = random_chain()
        bad = {k: v for k, v in ({"group": rng.choice([c.group_id, "X", 1, None]),
                                  "meeting": rng.choice(["M01", "ZZ", None, 7]),
                                  "root": rng.choice(["0" * 64, "", None, 123]),
                                  "root_seq": rng.choice([0, 1, 999, None, "3"]),
                                  "witnesses": rng.choice([["a", "b"], [], None, "ab", 5])}).items()
               if rng.random() < 0.85}
        if not bad:
            continue
        try:
            ok, det = verify_receipt(c, bad)
            t("fuzz.P10.%04d malformed receipt graceful" % i, True, det)
        except Exception as e:
            t("fuzz.P10.%04d malformed receipt graceful" % i, False, "%s: %r" % (type(e).__name__, e))
    return R

if __name__ == "__main__":
    res = run()
    ok = sum(1 for _, o, _ in res if o)
    print("%d/%d fuzz properties held (seed=%d)" % (ok, len(res), SEED))
    sys.exit(0 if ok == len(res) else 1)