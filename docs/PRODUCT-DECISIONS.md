# BAHI - Product & Trust Decisions

This document collects the **non-code** decisions the BAHI prototype must make
before it can be fielded as a real SHG ledger. These are not bugs and not (in
most cases) fixable by more hash math - they are product, governance, legal, and
operational choices. The audit (`bench/ATTACK-CATALOG.md`) and the round-3
hardening each cite these items as "theoretical / contextual" precisely because
they need a human decision, not a patch.

Each item is tagged:

- **ID** - stable identifier (for PR/issue cross-referencing).
- **Problem** - why it matters, and the attack it opens or closes.
- **Decision needed** - the choice a product owner / federation must make.
- **Status** - where the prototype currently stands.

---

## 1. Identity & KYC

### ID-1 - Member identity is an unverified string
**Problem.** A member is a free-form `member` string; nothing ties "Asha" to a
real human. Two people can both transact as "Asha", one person can be "Asha" in
meeting 1 and "Aasha" in meeting 2, and the ledger has no way to tell. This
undermines every per-member figure (balances, repeat_borrower, concentrated
lending) and enables impersonation and ghost-lender fraud.
**Decision needed.** What is the identity anchor - Aadhaar/eKYC, a federation-issued
member ID, biometric, or a self-sovereign identifier? Is identity established
once at enrolment and pinned for the life of the group?
**Status.** Prototype treats member names as opaque strings; no identity layer.

### ID-2 - Witness identity is not bound to a public key
**Problem.** Ed25519 (added in this PR) gives offline verification and
non-repudiation, but a public key still has to be bound to a real witness
out-of-band. An attacker who can swap "Meera's" public key for their own can
forge Meera's signature (see `tests.py` E4). No signature scheme solves this.
**Decision needed.** Who issues/registers witness keys, and how is a key
attested to belong to a named witness (key ceremony, notarized registry, KYC
linkage)?
**Status.** Keypairs are generated but there is no binding/registry.

### ID-3 - Roles are implicit
**Problem.** "Secretary", "witness", "member", "auditor" are conventions, not
enforced roles. The secretary holds full file control; nothing in the ledger
distinguishes a secretary's legitimate edit from an attacker's.
**Decision needed.** Are roles first-class (signed role claims), and which roles
can do what? Does the secretary have the write path by policy or by necessity?
**Status.** No role model; one demo "secretary" write path.

### ID-4 - Enrolment and off-boarding of members
**Problem.** A member joining or leaving changes the quorum denominator and the
set of valid members. Without a controlled join/leave event, ex-members keep
appearing in old receipts and new members lack binding.
**Decision needed.** How are members enrolled/off-boarded, and how does that
surface as a chain event (vs. a side-channel)?
**Status.** No join/leave semantics.

### ID-5 - Group identity is a string, not a registered entity
**Problem.** `group_id` ("G-RAJ-042") is hashed into every event (good), but the
string itself is not registered anywhere, so two groups can pick the same ID or
a malicious group can masquerade as another.
**Decision needed.** Is group identity registered/derived (e.g. from a federation
registry or an official group code)?
**Status.** Free-form `group_id`, no registry.

### ID-6 - Guardian / beneficiary identity for minors & joint accounts
**Problem.** SHG members can be minors or have joint accounts; receipts may need
to name a guardian or co-holder, which the current single `member` field cannot
express.
**Decision needed.** Does the ledger need guardian/co-holder fields, and how are
they bound and signed?
**Status.** Single `member` string only.

---

## 2. Key management & PKI

### KM-1 - Where do witness private keys live?
**Problem.** A witness private key stored on a shared phone or in the app's
unencrypted storage is stealable; one stored in a hardware token is cumbersome.
Key custody is the single biggest real-world risk to the Ed25519 path.
**Decision needed.** Key storage: mobile secure enclave / hardware token /
paper backup / HSM. What is the recovery story if a device is lost?
**Status.** Keys are in-memory only (demo); no persistence or custody policy.

### KM-2 - Key rotation
**Problem.** Witness keys must rotate (compromise, device loss, periodic policy).
Rotation must not invalidate old receipts - old receipts must remain verifiable
against the old key that signed them.
**Decision needed.** Rotation cadence and how historical keys are retained and
served for receipt verification.
**Status.** No rotation; a key is assumed permanent.

### KM-3 - Key revocation / compromise response
**Problem.** If Meera's private key is stolen, every receipt she signed after the
theft is suspect, but every one before it is fine. Revocation must be timestamped
and ride the chain so verifiers know which signatures to trust.
**Decision needed.** Revocation mechanism (revocation event, CRL-style list) and
its effect on already-issued receipts.
**Status.** No revocation.

### KM-4 - Passphrase strength & derivation (legacy HMAC path)
**Problem.** The HMAC path derives witness keys from `"pass-" + name`, which is
demo-grade. Real passphrases need a KDF (scrypt/Argon2id), salt, and minimum
entropy; otherwise the "shared secret" is guessable.
**Decision needed.** Migrate HMAC to a memory-hard KDF with per-group salt, or
deprecate HMAC entirely in favor of Ed25519.
**Status.** SHA-256 HMAC over a low-entropy demo passphrase.

### KM-5 - Who holds the secretary's write key?
**Problem.** The write path (append events) needs its own authorization. Today it
is unauthenticated; anyone with file access can append.
**Decision needed.** Sign appends with a secretary key? Multi-sig for writes?
**Status.** Writes are unauthenticated.

### KM-6 - Key escrow & recovery for the group corpus
**Problem.** If the only key-holder dies or loses the key, the group's ability to
close meetings and issue receipts stalls. SHGs are low-tech; key loss is common.
**Decision needed.** Escrow/backup scheme (m-of-n shards among members, paper
recovery codes), and who may trigger recovery.
**Status.** No escrow; key loss = permanent lockout of the crypto path.

### KM-7 - Threshold signatures vs. individual signatures
**Problem.** Today each witness signs individually and quorum is checked by
counting distinct names. A threshold scheme (t-of-n) would let any 2 of 5
witnesses jointly sign without revealing which - a different trust model with
different privacy properties.
**Decision needed.** Individual signatures (current) vs. threshold/multisig?
**Status.** Individual Ed25519/HMAC signatures with a `MIN_WITNESSES` count.

### KM-8 - Signing device / UI trust
**Problem.** Signatures are only as good as the device that made them. A
compromised phone signs whatever the malware asks, and the user has no way to
see what they signed (what root, what meeting).
**Decision needed.** Transaction-display hardening (WYSIWYS - show the exact
bytes/root being signed on the signing device).
**Status.** No display-independent signing UI.

---

## 3. Witness model & governance

### WT-1 - Who may witness, and conflict-of-interest rules
**Problem.** A witness who is also the borrower (or the borrower's spouse) is
conflicted. Today `MIN_WITNESSES = 2` with no independence requirement.
**Decision needed.** Independence rules: may a witness be a party to the meeting
they sign? Must witnesses be non-members or from another group?
**Status.** No independence rule; witnesses can be anyone named in the chain.

### WT-2 - Quorum threshold (2 is arbitrary)
**Problem.** `MIN_WITNESSES = 2` is hard-coded. Larger groups or higher-value
meetings may need 3, or a quorum proportional to group size.
**Decision needed.** What is the right quorum (and is it per-meeting-type)?
**Status.** Hard-coded 2.

### WT-3 - External / independent witness (notarization)
**Problem.** An all-internal witness set can collude. An external witness - a
neighboring group's officer, a federation node, a notary, or a public
timestamp/notary service - breaks collusion.
**Decision needed.** Is there an external witness role, and what does it attest?
**Status.** No external witness.

### WT-4 - Witness liability & legal standing
**Problem.** A signature has legal meaning only if the witness understands and
accepts liability. For a real ledger, witness signatures may need to carry legal
weight (Indian Evidence Act, IT Act s.85 digital-signature provisions).
**Decision needed.** What legal status do witness signatures carry, and what
disclaimer/consent do witnesses sign?
**Status.** Signatures are cryptographic only, no legal framework.

### WT-5 - Meeting cadence & agenda binding
**Problem.** The ledger has no notion of a meeting agenda or schedule; a "meeting"
is just a close event. Off-agenda or unscheduled closes are indistinguishable
from scheduled ones.
**Decision needed.** Bind closes to a scheduled meeting identity/agenda?
**Status.** `meeting_id` is a free-form string.

---

## 4. Storage & anchoring

### ST-1 - Append-only / WORM storage guarantee
**Problem.** The hash chain detects retroactive edits *after* witnessing, but the
bookkeeper with full file control can still rewrite everything consistently at
entry time. Detection depends on members holding independent copies of receipts.
**Decision needed.** Store the chain on append-only media (WORM, immutable object
store) so even the bookkeeper cannot rewrite history.
**Status.** Plain JSON file; no WORM.

### ST-2 - External/public anchoring of roots
**Problem.** A root hash is only as trustworthy as the copies held by members.
Publishing roots to an external anchor (a public blockchain, a notary service,
a newspaper, a federation bulletin) makes later rewrite detectable by anyone.
**Decision needed.** Anchor roots externally? Which anchor (cost, latency, privacy)?
**Status.** No external anchor.

### ST-3 - Backup & durability of the single JSON file
**Problem.** `save()` writes one JSON file (+ `.bak`). A single lost phone/disk
loses the ledger. The `.bak` is a best-effort copy in the same directory.
**Decision needed.** Replication policy (N copies, off-site, federation mirror).
**Status.** Local file + best-effort `.bak`.

### ST-4 - Retention & archival of old meetings
**Problem.** Chains grow forever; at 1M events the chain is ~250 MB in memory.
Long-term retention needs pruning/archival that does NOT break verification of
old receipts (roots must stay verifiable forever).
**Decision needed.** Retention policy and how archived segments stay verifiable.
**Status.** No retention; unbounded growth.

### ST-5 - Storage format versioning & migration
**Problem.** The JSON schema will change (it already has: witness records gained
`verify_key`). Old files must load under new code or fail clearly.
**Decision needed.** Schema version field + migration policy.
**Status.** No version field; `load()` tolerates missing fields defensively.

### ST-6 - Clock / timestamp trust
**Problem.** Event `ts` is a free-form string supplied by the secretary; it is
not trusted time. Ordering is enforced by seq, but "when" is whatever the
secretary typed.
**Decision needed.** Trusted timestamping (signed time, NTP, anchor time)?
**Status.** Untrusted free-form `ts`.

---

## 5. Network & federation

### NW-1 - Sync & conflict resolution between nodes
**Problem.** The prototype is single-file. A federation means multiple nodes
(secretary phone, member copies, federation server) that must converge, and
concurrent appends must be merged without breaking the chain.
**Decision needed.** Sync protocol and conflict rules (last-write-wins? CRDT?
append-only replication with a single writer per group?).
**Status.** No sync; single writer assumed.

### NW-2 - Node trust & byzantine tolerance
**Problem.** If the federation node is malicious or compromised, it can withhold,
reorder, or serve stale chains. Verifiers need protection against a dishonest
node, not just a crashed one.
**Decision needed.** How many nodes must agree, and what do members do if the
federation node disagrees with their receipt?
**Status.** No federation; node trust is implicit.

### NW-3 - Transport security & authentication
**Problem.** The demo server is HTTP on localhost with a Host/Origin allowlist
(not authentication). A real deployment needs TLS and authenticated endpoints.
**Decision needed.** TLS everywhere; how do clients authenticate to the server
and vice versa (mTLS, tokens)?
**Status.** Plain HTTP, no auth, localhost-scoped.

### NW-4 - Offline-first operation & reconciliation
**Problem.** SHG meetings are often offline (low connectivity). The ledger must
work fully offline and reconcile later, including conflict detection when two
devices both appended while disconnected.
**Decision needed.** Offline model and reconciliation rules.
**Status.** Fully offline already, but no multi-device reconciliation.

---

## 6. Privacy & consent

### PR-1 - What is public, and to whom?
**Problem.** The chain contains member names and amounts in plaintext. In the
federation view, who may read whose balances? SHG financial data is sensitive.
**Decision needed.** Access control / visibility model (member sees own + group
aggregates; auditor sees redacted; federation sees hashes only?).
**Status.** Everything is plaintext and world-readable to anyone with the file.

### PR-2 - Data minimisation & field exposure
**Problem.** Receipts carry member event hashes and names; they may carry more
than a member needs. Minimising fields reduces leakage.
**Decision needed.** Which fields are strictly necessary on the receipt?
**Status.** Receipts carry member_events (seq+hash) + witness records.

### PR-3 - Regulatory compliance (DPDP Act 2023, IT Act)
**Problem.** India's Digital Personal Data Protection Act and IT Act impose
consent, purpose-limitation, and breach-notification duties. Storing financial
data in plaintext hashes may still expose personal data (names are personal data
even if hashed alongside).
**Decision needed.** Consent capture, data-subject rights, breach policy, and
lawful-basis documentation.
**Status.** No compliance posture.

### PR-4 - Right to erasure vs. append-only immutability
**Problem.** Data-protection law gives a "right to erasure", but an append-only
ledger cannot delete. This is a fundamental tension that needs a legal position
(e.g. pseudonymisation, or lawful-basis exemption).
**Decision needed.** How to reconcile erasure rights with immutability.
**Status.** Append-only, no deletion, no legal position.

---

## Summary

| Category | Count | Items |
|---|---|---|
| Identity & KYC | 6 | ID-1 … ID-6 |
| Key management & PKI | 8 | KM-1 … KM-8 |
| Witness model & governance | 5 | WT-1 … WT-5 |
| Storage & anchoring | 6 | ST-1 … ST-6 |
| Network & federation | 4 | NW-1 … NW-4 |
| Privacy & consent | 4 | PR-1 … PR-4 |
| **Total** | **33** | |

**What this PR already resolved** (so these are the *remaining* decisions):

- The **HMAC-symmetric caveat** (offline witness verification) is solved by
  Ed25519 - see KM items for what that solution *still* needs (binding, custody,
  rotation, revocation).
- Quorum gaming, legacy-receipt binding, CSV/XSS injection, and the audit blind
  spots (corpus insolvency, repeat borrower, orphan correction) are fixed and
  surfaced in the auditor panel.

Nothing in this document is fixable by more code in isolation - each item needs
an owner, a product decision, and (often) a legal or operational process. Track
them as issues; do not let them silently become "later".
