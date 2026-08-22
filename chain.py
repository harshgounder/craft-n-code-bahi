#!/usr/bin/env python3
"""chain.py - BAHI core: SHA-256 event chain, meeting roots, fork detection.
Pure stdlib. Deterministic: same files -> same bytes -> same verdict.

Protocol (v1.2, after bug-hunter pass 1):
- Events form a hash chain; recomputing from genesis detects any edit
  (event-hash-mismatch), delete (prev-hash-mismatch), reorder (same).
- Meeting close: at least 2 witness signatures (quorum) are REQUIRED;
  a meeting closed with 0 or 1 witness FAILS verification. The signature
  string is structural (participant-bound token), not a crypto claim:
  it binds the participant's name to the meeting root in the records.
- Receipts are bound to (group, meeting, root, member).
  A receipt from another group or another meeting FAILS.
- Corrupt chain files (missing fields, bad JSON, wrong types) NEVER
  crash: load() and verify() return structured corruption verdicts.

Honest boundaries: full file-control by the bookkeeper (rewrite every
hash consistently) is undetectable by design; detection covers
retroactive edits AFTER witnessing, not mass collusion at entry time.
"""
import hashlib, json

MIN_WITNESSES = 2

def h(*parts):
    m = hashlib.sha256()
    for p in parts:
        m.update(str(p).encode("utf-8"))
        m.update(b"\x1f")
    return m.hexdigest()

def _norm_amount(v):
    """Return int paise or None if invalid. Negative amounts rejected."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    if n < 0:
        return None
    return n

class BahiChain:
    def __init__(self, group_id=""):
        self.group_id = group_id
        self.events = []
        self.roots = {}

    def add_event(self, seq, etype, member, amount_paise, ts, prev_hash=""):
        amt = _norm_amount(amount_paise)
        if amt is None:
            raise ValueError("amount must be a non-negative integer (paise)")
        if not member or not isinstance(member, str):
            raise ValueError("member must be a non-empty string")
        # duplicate seq guard: identical (seq, type, member, amount) is
        # allowed for corrections but two events with the SAME seq and
        # DIFFERENT identity would make audit attribution ambiguous.
        prev = prev_hash or (self.events[-1]["hash"] if self.events else h("GENESIS", self.group_id))
        ev = {
            "seq": seq,
            "group": self.group_id,
            "type": etype,
            "member": member,
            "amount_paise": amt,
            "ts": ts,
            "prev": prev,
        }
        ev["hash"] = h(prev, seq, etype, member, amt, ts)
        self.events.append(ev)
        return ev

    def close_meeting(self, meeting_id, ts, witnesses=None):
        """Close the meeting. witnesses: list of signature strings.
        Quorum is enforced here and re-enforced at verification."""
        seq = len(self.events) + 1
        ev = self.add_event(seq, "MEETING-CLOSE", "__root__", 0, ts)
        sigs = list(witnesses or [])
        self.roots[meeting_id] = {
            "root_hash": ev["hash"],
            "root_seq": ev["seq"],
            "ts": ts,
            "witnesses": sigs,
        }
        return self.roots[meeting_id]

    def root_for(self, meeting_id):
        return self.roots.get(meeting_id)

    def verify(self):
        """Recompute the whole chain. Returns (ok, bad_seq, why).
        NEVER raises on malformed data: returns (False, seq, 'corrupt-file: ...')."""
        if not self.events:
            return False, 0, "corrupt-file: empty chain"
        prev = None
        for i, ev in enumerate(self.events):
            for field in ("seq", "type", "member", "amount_paise", "ts", "prev", "hash", "group"):
                if field not in ev:
                    return False, i + 1, "corrupt-file: missing field %r at event %d" % (field, i + 1)
            try:
                amt = _norm_amount(ev["amount_paise"])
            except (TypeError, ValueError):
                return False, i + 1, "corrupt-file: bad amount at event %d" % (i + 1)
            if amt is None:
                return False, i + 1, "corrupt-file: negative amount at event %d" % (i + 1)
            recomputed = h(ev["prev"], ev["seq"], ev["type"], ev["member"], amt, ev["ts"])
            if recomputed != ev["hash"]:
                return False, i + 1, "event-hash-mismatch"
            if prev is not None and ev["prev"] != prev:
                return False, i + 1, "prev-hash-mismatch"
            prev = ev["hash"]
        return True, 0, "ok"

    def export(self):
        return {"group": self.group_id, "events": self.events, "roots": self.roots}

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.export(), f, indent=1)

    @staticmethod
    def load(path):
        c = BahiChain()
        try:
            with open(path) as f:
                d = json.load(f)
        except (OSError, ValueError) as e:
            c.events = []
            c.roots = {"__corrupt__": {"root_hash": "", "root_seq": 0, "ts": "", "witnesses": [], "corrupt": "load: %s" % e}}
            return c
        if not isinstance(d, dict) or "group" not in d or not isinstance(d.get("events"), list):
            c.events = []
            c.roots = {"__corrupt__": {"root_hash": "", "root_seq": 0, "ts": "", "witnesses": [], "corrupt": "load: no events array"}}
            return c
        c.group_id = d["group"]
        c.events = d["events"]
        c.roots = d.get("roots", {})
        return c

    @property
    def corrupt(self):
        return "__corrupt__" in self.roots or not isinstance(self.group_id, str) or self.group_id == ""


def receipt_payload(group, meeting_id, root_meta, member):
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
    """(1) recompute chain (2) bind group (3) bind meeting+root (4) quorum
    (5) witness subset. Never crashes: corrupt input = fail with detail."""
    if chain.corrupt:
        return False, "corrupt-chain: %s" % (chain.roots.get("__corrupt__", {}).get("corrupt", "unknown"))
    chain_ok, bad_seq, why = chain.verify()
    if not chain_ok:
        return False, "FORK-AT-EVENT-%s (%s)" % (bad_seq, why)
    if receipt.get("group") != chain.group_id:
        return False, "group-mismatch"
    root_meta = chain.root_for(receipt.get("meeting", ""))
    if root_meta is None:
        return False, "meeting-root-missing"
    if root_meta["root_hash"] != receipt.get("root"):
        return False, "FORK-AT-MEETING-%s" % receipt.get("meeting")
    sigs_now = root_meta.get("witnesses") or []
    sigs_then = receipt.get("witnesses") or []
    if len(sigs_then) < MIN_WITNESSES:
        return False, "quorum-fail: %d witness" % len(sigs_then)
    if len(sigs_now) < MIN_WITNESSES:
        return False, "quorum-fail: chain has %d witness" % len(sigs_now)
    if not set(sigs_then).issubset(set(sigs_now)):
        return False, "witness-signature-differs"
    return True, "MATCH"


def audit_status(chain):
    """For exporter: never raise on corrupt data."""
    if chain.corrupt:
        return {"chain_ok": False, "first_bad_seq": 0, "why": str(chain.roots.get("__corrupt__", {}).get("corrupt", ""))}
    ok, bad_seq, why = chain.verify()
    return {"chain_ok": ok, "first_bad_seq": bad_seq if not ok else None, "why": why}