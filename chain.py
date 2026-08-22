#!/usr/bin/env python3
"""chain.py - BAHI core: SHA-256 event chain, meeting roots, fork detection.
Pure stdlib. Deterministic: same files -> same bytes -> same verdict.

Design notes:
- Events form a pure hash chain (prev -> hash). No witness fields inside
  the hashed event (avoids circular hash<->signature dependency).
- Meeting close: a MEETING-CLOSE event terminates the meeting's segment.
  Its hash is the MEETING ROOT, stored as metadata in roots[].
- Witnesses sign the ROOT VALUE (outside the chain) and their signatures
  are stored as metadata, never inside a hashed event.
- Verification: recompute the ENTIRE chain from genesis; then compare the
  receipt root against the recomputed meeting root. Any internal break
  = FORK even if a stored root string still matches."""
import hashlib, json

def h(*parts):
    hsh = hashlib.sha256()
    for p in parts:
        if isinstance(p, str):
            hsh.update(p.encode("utf-8"))
        elif isinstance(p, (int, float)):
            hsh.update(str(p).encode("utf-8"))
        elif isinstance(p, bytes):
            hsh.update(p)
        else:
            hsh.update(json.dumps(p, sort_keys=True).encode("utf-8"))
    return hsh.hexdigest()

class BahiChain:
    def __init__(self, group_id=""):
        self.group_id = group_id
        self.events = []          # list of event dicts (hashed fields only)
        self.roots = {}           # meeting_id -> {"root_hash","root_seq","ts","witnesses":[]}

    def add_event(self, seq, etype, member, amount_paise, ts, prev_hash=""):
        prev = prev_hash or (self.events[-1]["hash"] if self.events else h("GENESIS", self.group_id))
        ev = {
            "seq": seq,
            "group": self.group_id,
            "type": etype,           # contribution | loan | repayment | correction | MEETING-CLOSE
            "member": member,
            "amount_paise": int(amount_paise),
            "ts": ts,
            "prev": prev,
        }
        ev["hash"] = h(prev, seq, etype, member, ev["amount_paise"], ts)
        self.events.append(ev)
        return ev

    def close_meeting(self, meeting_id, ts):
        # distinct seq: never collide with the last contribution event
        ev = self.add_event(len(self.events) + 1, "MEETING-CLOSE", "__root__", 0, ts)
        self.roots[meeting_id] = {
            "root_hash": ev["hash"],
            "root_seq": ev["seq"],
            "ts": ts,
            "witnesses": [],       # signatures over root_hash, added after close
        }
        return self.roots[meeting_id]

    def export(self):
        return {"group": self.group_id, "events": self.events, "roots": self.roots}

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.export(), f, indent=1)

    @staticmethod
    def load(path):
        c = BahiChain()
        with open(path) as f:
            d = json.load(f)
        c.group_id = d["group"]
        c.events = d["events"]
        c.roots = d.get("roots", {})
        return c

    def verify(self):
        """Recompute the whole chain. Returns (ok, first_bad_seq, detail)."""
        prev = h("GENESIS", self.group_id)
        for ev in self.events:
            recomputed = h(ev["prev"], ev["seq"], ev["type"], ev["member"],
                           ev["amount_paise"], ev["ts"])
            if ev["prev"] != prev:
                return False, ev["seq"], "prev-hash-mismatch"
            if ev["hash"] != recomputed:
                return False, ev["seq"], "event-hash-mismatch"
            prev = ev["hash"]
        return True, None, "chain-ok"

    def root_for(self, meeting_id):
        return self.roots.get(meeting_id)

def receipt_payload(group, meeting_id, root_meta, member):
    """root_meta = chain.roots[meeting_id] after witnesses attached."""
    return {
        "group": group,
        "meeting": meeting_id,
        "root": root_meta["root_hash"],
        "root_seq": root_meta["root_seq"],
        "member": member,
        "root_ts": root_meta["ts"],
        "witnesses": root_meta["witnesses"],
    }

def verify_receipt(chain, receipt):
    """Correct protocol: (1) recompute the ENTIRE chain from genesis; any
    internal break = fork even if a stored root string matches.
    (2) compare receipt root against recomputed meeting root.
    (3) witness signatures stored at close must be a superset of receipt's.
    Returns (ok, detail)."""
    chain_ok, bad_seq, why = chain.verify()
    if not chain_ok:
        return False, "FORK-AT-EVENT-%s (%s)" % (bad_seq, why)
    root_meta = chain.root_for(receipt["meeting"])
    if root_meta is None:
        return False, "meeting-root-missing"
    if root_meta["root_hash"] != receipt["root"]:
        return False, "FORK-AT-MEETING-%s" % receipt["meeting"]
    sigs_now = set(root_meta["witnesses"])
    sigs_then = set(receipt["witnesses"])
    if not sigs_then.issubset(sigs_now):
        return False, "witness-signature-differs"
    return True, "MATCH"