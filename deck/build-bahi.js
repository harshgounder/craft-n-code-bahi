// BAHI - Craft N Code Round 1 deck (official template design language)
// Build: node build-sakshi.js  |  Screenshots: drop entry.png / receipt.png / fork.png / auditor.png into ss/ and re-run
"use strict";
const pptxgen = require("pptxgenjs");
const fs = require("fs");

const pptx = new pptxgen();
pptx.layout = "LAYOUT_16x9";
pptx.author = "Team 511";
pptx.title = "BAHI - Member-Witnessed Verification Layer (PS-17)";
pptx.subject = "Craft N Code 2026 Round 1";

// ---- design tokens (from official template render) ----
const BG = "0D0B09";        // near-black warm
const PANEL = "6B3A33";     // muted reddish brown content boxes
const PANEL2 = "59312B";
const ORANGE = "F28C28";    // accent
const WHITE = "FFFFFF";
const MUTED = "C9B8A8";
const SERIF = "Georgia";
const SANS = "Trebuchet MS";
const MONO = "Courier New";

const W = 10, H = 5.625;

function glow(slide, yBase) {
  // bottom orange glow wave (translucent ellipses) + dot mesh
  slide.addShape("ellipse", { x: -1.5, y: yBase, w: 13, h: 1.1, fill: { color: ORANGE, transparency: 88 }, line: { type: "none" } });
  slide.addShape("ellipse", { x: -0.8, y: yBase + 0.28, w: 11.6, h: 0.85, fill: { color: ORANGE, transparency: 80 }, line: { type: "none" } });
  slide.addShape("ellipse", { x: 0.2, y: yBase + 0.55, w: 9.6, h: 0.7, fill: { color: ORANGE, transparency: 66 }, line: { type: "none" } });
  for (let i = 0; i < 14; i++) {
    slide.addShape("ellipse", {
      x: 0.3 + i * 0.75, y: yBase + 0.02 + ((i * 37) % 5) * 0.07, w: 0.045, h: 0.045,
      fill: { color: i % 3 ? WHITE : ORANGE, transparency: 45 }, line: { type: "none" }
    });
  }
}

function chrome(slide, pageNo) {
  slide.addText("CRAFT N CODE 2.0", { x: 0.35, y: 0.18, w: 3, h: 0.3, fontFace: MONO, fontSize: 8.5, color: ORANGE, charSpacing: 2, align: "left" });
  slide.addText("BAHI  |  R1", { x: 6.65, y: 0.18, w: 3, h: 0.3, fontFace: MONO, fontSize: 8.5, color: MUTED, align: "right" });
  slide.addText(String(pageNo).padStart(2, "0"), { x: 9.3, y: 5.28, w: 0.55, h: 0.25, fontFace: MONO, fontSize: 8.5, color: MUTED, align: "right" });
  slide.addShape("line", { x: 0.35, y: 0.52, w: 9.3, h: 0, line: { color: ORANGE, width: 0.75, transparency: 55 } });
}

function header(slide, text, sub) {
  slide.addText(text, { x: 0.6, y: 0.72, w: 8.8, h: 0.75, fontFace: SERIF, fontSize: 30, bold: true, color: WHITE, align: "center" });
  if (sub) slide.addText(sub, { x: 0.6, y: 1.44, w: 8.8, h: 0.35, fontFace: SANS, fontSize: 12, color: MUTED, align: "center", italic: true });
}

function panel(slide, x, y, w, h, fill) {
  return slide.addShape("roundRect", { x, y, w, h, rectRadius: 0.06, fill: { color: fill || PANEL }, line: { color: "8C5A4E", width: 0.5, transparency: 40 } });
}

function bullets(slide, x, y, w, h, items, mono) {
  slide.addText(items.map(t => ({ text: t, options: { bullet: { code: "2022", indent: 12 }, breakLine: true } })), {
    x, y, w, h, fontFace: mono ? MONO : SANS, fontSize: 11.5, color: WHITE, valign: "top", lineSpacing: 14, paraSpaceAfter: 5
  });
}

// ============ SLIDE 1: TITLE ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.25);
  s.addText("CRAFT N CODE 2.0", { x: 0.5, y: 0.35, w: 9, h: 0.4, fontFace: MONO, fontSize: 11, color: ORANGE, charSpacing: 3, align: "center" });
  s.addText("BAHI", { x: 0.5, y: 1.15, w: 9, h: 1.2, fontFace: SERIF, fontSize: 72, bold: true, color: WHITE, align: "center" });
  s.addText("Member-Witnessed Verification Layer for the SHG Digital Ledger", { x: 0.8, y: 2.25, w: 8.4, h: 0.45, fontFace: SANS, fontSize: 15, color: MUTED, align: "center" });
  s.addText([
    { text: "Title", options: { fontFace: SANS, fontSize: 13, color: ORANGE, breakLine: true } },
    { text: "The person who records the money is no longer the only proof.", options: { fontFace: SANS, fontSize: 15, color: WHITE, breakLine: true, paraSpaceAfter: 10 } },
    { text: "Track", options: { fontFace: SANS, fontSize: 13, color: ORANGE, breakLine: true } },
    { text: "PS-17  SHG Digital Ledger - Tamper-Evident Financial Logs", options: { fontFace: SANS, fontSize: 15, color: WHITE, breakLine: true, paraSpaceAfter: 10 } },
    { text: "Team Name (as registered)", options: { fontFace: SANS, fontSize: 13, color: ORANGE, breakLine: true } },
    { text: "Team 511  (confirm against portal at login)", options: { fontFace: SANS, fontSize: 15, color: WHITE, breakLine: true } },
  ], { x: 0.7, y: 3.15, w: 8.4, h: 1.9, valign: "top" });
}

// ============ SLIDE 2: PROBLEM STATEMENT ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 2);
  header(s, "Problem Statement");
  const p = panel(s, 0.6, 1.95, 8.8, 3.15);
  s.addText([
    { text: "1 crore+ SHGs still run on handwritten registers.", options: { breakLine: true, bold: true, fontSize: 14, paraSpaceAfter: 10 } },
    { text: "Bookkeeping errors, disputes over who owes what, and embezzlement by office-bearers often go undetected until the savings are gone.", options: { breakLine: true, fontSize: 12, paraSpaceAfter: 12 } },
    { text: "Scale: 10.03 crore women members (DAY-NRLM), 144.22 lakh savings-linked SHG bank accounts (NABARD).", options: { breakLine: true, fontSize: 12, paraSpaceAfter: 12 } },
    { text: "LokOS already digitizes the books (94.16 lakh SHGs). But it is server-authoritative: a member cannot verify a single entry about her own money, offline, ever.", options: { breakLine: true, fontSize: 12, paraSpaceAfter: 12 } },
    { text: "The gap is not digitization. It is verification.", options: { breakLine: true, bold: true, fontSize: 14 } },
  ], { x: 0.95, y: 2.2, w: 8.1, h: 2.6, fontFace: SANS, color: WHITE, valign: "top", lineSpacing: 15 });
}

// ============ SLIDE 3: TECH STACK + METHODOLOGY ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 3);
  header(s, "Technical Approach", "Stack and method, chosen for the 7h window");
  panel(s, 0.6, 1.9, 4.25, 3.2);
  s.addText("Tech Stack", { x: 0.85, y: 2.05, w: 3.8, h: 0.35, fontFace: SERIF, fontSize: 17, bold: true, color: ORANGE });
  bullets(s, 0.85, 2.45, 3.85, 2.5, [
    "Python 3.11+ stdlib only, zero dependencies",
    "SHA-256 hash chain (append-only)",
    "HMAC-SHA256 witness MACs, demo-mode label",
    "SQLite transactional state",
    "Static HTML/CSS/JS UI, loopback server",
    "QR receipts, printable, byte-short",
    "Fully offline, zero APIs at runtime",
  ]);
  panel(s, 5.15, 1.9, 4.25, 3.2);
  s.addText("Methodology", { x: 5.4, y: 2.05, w: 3.8, h: 0.35, fontFace: SERIF, fontSize: 17, bold: true, color: ORANGE });
  bullets(s, 5.4, 2.45, 3.85, 2.5, [
    "4-icon entry (contribution, loan, repayment, correction) + voice repeat",
    "Green-tick confirm before any event enters the chain",
    "Append-only: no UPDATE, no DELETE. Corrections = reversal + replacement",
    "2 witness keys sign the meeting-close root",
    "Member receipt: root + witnesses, QR or text",
    "Verification recomputes every hash, offline: MATCH or FORK AT EVENT n",
    "Deterministic: same files, same bytes, same verdict",
  ]);
}

// ============ SLIDE 4: IMPLEMENTATION + FLOWCHART ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 4);
  header(s, "Implementation and Flow");
  // flowchart row 1
  const boxes = [
    { t: "Member taps icon", x: 0.55 },
    { t: "Voice repeat, green tick", x: 2.45 },
    { t: "Event appended", x: 4.35 },
    { t: "Meeting close, 2 witnesses sign", x: 6.25 },
    { t: "Receipt QR to member", x: 8.15 },
  ];
  boxes.forEach((b, i) => {
    s.addShape("roundRect", { x: b.x, y: 2.35, w: 1.7, h: 0.75, rectRadius: 0.08, fill: { color: PANEL }, line: { color: ORANGE, width: 0.75, transparency: 30 } });
    s.addText(b.t, { x: b.x + 0.05, y: 2.42, w: 1.6, h: 0.6, fontFace: SANS, fontSize: 9.5, color: WHITE, align: "center", valign: "middle" });
    if (i < boxes.length - 1) s.addShape("line", { x: b.x + 1.7, y: 2.72, w: 0.75, h: 0, line: { color: ORANGE, width: 1.5, endArrowType: "triangle" } });
  });
  // row 2
  s.addShape("roundRect", { x: 1.15, y: 3.45, w: 1.9, h: 0.65, rectRadius: 0.08, fill: { color: PANEL2 }, line: { color: MUTED, width: 0.5 } });
  s.addText("Secretary exports chain files", { x: 1.2, y: 3.5, w: 1.8, h: 0.55, fontFace: SANS, fontSize: 9, color: WHITE, align: "center", valign: "middle" });
  s.addShape("line", { x: 3.05, y: 3.78, w: 0.7, h: 0, line: { color: MUTED, width: 1.5, endArrowType: "triangle" } });
  s.addShape("roundRect", { x: 3.75, y: 3.45, w: 1.9, h: 0.65, rectRadius: 0.08, fill: { color: PANEL2 }, line: { color: MUTED, width: 0.5 } });
  s.addText("Auditor recomputes roots", { x: 3.8, y: 3.5, w: 1.8, h: 0.55, fontFace: SANS, fontSize: 9, color: WHITE, align: "center", valign: "middle" });
  s.addShape("line", { x: 5.65, y: 3.78, w: 0.6, h: 0, line: { color: MUTED, width: 1.5, endArrowType: "triangle" } });
  s.addShape("roundRect", { x: 6.25, y: 3.35, w: 1.5, h: 0.85, rectRadius: 0.08, fill: { color: "2E7D32" }, line: { color: WHITE, width: 0.75, transparency: 40 } });
  s.addText("MATCH", { x: 6.25, y: 3.45, w: 1.5, h: 0.3, fontFace: MONO, fontSize: 13, bold: true, color: WHITE, align: "center" });
  s.addText("receipt verifies", { x: 6.25, y: 3.75, w: 1.5, h: 0.25, fontFace: SANS, fontSize: 8.5, color: WHITE, align: "center" });
  s.addShape("roundRect", { x: 7.95, y: 3.35, w: 1.5, h: 0.85, rectRadius: 0.08, fill: { color: "B3261E" }, line: { color: WHITE, width: 0.75, transparency: 40 } });
  s.addText("FORK AT n", { x: 7.95, y: 3.45, w: 1.5, h: 0.3, fontFace: MONO, fontSize: 13, bold: true, color: WHITE, align: "center" });
  s.addText("tamper detected", { x: 7.95, y: 3.75, w: 1.5, h: 0.25, fontFace: SANS, fontSize: 8.5, color: WHITE, align: "center" });
  s.addShape("line", { x: 6.25, y: 2.72, w: 2.4, h: 0, line: { color: MUTED, width: 0.75, transparency: 40 } });
  bullets(s, 0.55, 4.45, 8.9, 0.95, [
    "Implementation: chain.py, witness.py, receipt.py, loader.py; attack test matrix (edit, delete, reorder, double-spend)",
    "Failure drill: no-network, corrupt fixture, port conflict, repeat reset. Reproducibility is auditability.",
  ], true);
}

// ============ SLIDE 5: PROTOTYPE ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 5);
  header(s, "Prototype", "Real demo, captured from the running app before freeze");
  const shots = [
    { f: "entry", t: "4-icon entry + voice confirm" },
    { f: "receipt", t: "Member receipt (QR + root)" },
    { f: "fork", t: "Fork alert: FORK AT MEETING M07" },
    { f: "auditor", t: "Auditor view + export" },
  ];
  shots.forEach((sh, i) => {
    const x = 0.55 + i * 2.3, w = 2.1;
    const has = fs.existsSync("ss/" + sh.f + ".png");
    if (has) {
      s.addShape("roundRect", { x, y: 2.05, w, h: 2.35, rectRadius: 0.06, fill: { color: "171310" }, line: { color: ORANGE, width: 0.75, transparency: 35 } });
      s.addImage({ path: "ss/" + sh.f + ".png", x: x + 0.07, y: 2.12, w: w - 0.14, h: 1.95, sizing: { type: "contain", w: w - 0.14, h: 1.95 } });
    } else {
      panel(s, x, 2.05, w, 2.35, PANEL2);
      s.addText("SCREENSHOT\nSLOT", { x, y: 2.85, w, h: 0.8, fontFace: MONO, fontSize: 11, color: MUTED, align: "center" });
    }
    s.addText(sh.t, { x: x - 0.05, y: 4.45, w: w + 0.1, h: 0.6, fontFace: SANS, fontSize: 9.5, color: WHITE, align: "center" });
  });
  s.addText("Every screenshot is the real running app: entry, receipt, fork alert, auditor. Nothing is photoshopped.", {
    x: 0.55, y: 5.02, w: 8.9, h: 0.3, fontFace: MONO, fontSize: 8, color: MUTED, align: "center"
  });
}

// ============ SLIDE 6: CHALLENGES AND RISKS ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 6);
  header(s, "Challenges and Risks");
  panel(s, 0.6, 1.9, 4.25, 3.3);
  s.addText("What we do NOT claim", { x: 0.85, y: 2.05, w: 3.8, h: 0.35, fontFace: SERIF, fontSize: 16, bold: true, color: ORANGE });
  bullets(s, 0.85, 2.45, 3.85, 2.6, [
    "No security audit claim",
    "No embezzlement detection claim",
    "No PKI-grade signatures (witness MAC, labeled)",
    "No Aadhaar / OTP / KYC",
    "No server persistence, no live LokOS sync",
    "No ML. Honesty is the product",
    "Not fraud prevention: detection with a member-held artifact",
  ]);
  panel(s, 5.15, 1.9, 4.25, 3.3);
  s.addText("Build risks and mitigations", { x: 5.4, y: 2.05, w: 3.8, h: 0.35, fontFace: SERIF, fontSize: 16, bold: true, color: ORANGE });
  bullets(s, 5.4, 2.45, 3.85, 2.6, [
    "QR on feature phones: byte-short payload, text fallback",
    "Voice confirm on low-end audio: constrained repeat, icon fallback",
    "Frozen data drift: all sources saved with SHA-256 in manifest",
    "7h window: stdlib only, deterministic fixtures, one-command reset",
    "Attack button in demo proves the detection claim live",
  ]);
}

// ============ SLIDE 7: IMPACT AND BENEFITS ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 7);
  header(s, "Impact and Benefits");
  panel(s, 0.6, 1.9, 4.25, 3.15);
  s.addText("Member", { x: 0.85, y: 2.05, w: 3.8, h: 0.35, fontFace: SERIF, fontSize: 16, bold: true, color: ORANGE });
  bullets(s, 0.85, 2.45, 3.85, 2.45, [
    "Owns verifiable evidence of her own money",
    "Receipt catches alteration instantly, offline",
    "No trust in bookkeeper, vendor, cloud, or chain",
    "Works on basic phones: print QR or copied text",
  ]);
  panel(s, 5.15, 1.9, 4.25, 3.15);
  s.addText("Federation and system", { x: 5.4, y: 2.05, w: 3.8, h: 0.35, fontFace: SERIF, fontSize: 16, bold: true, color: ORANGE });
  bullets(s, 5.4, 2.45, 3.85, 2.45, [
    "Block/district audit remotely, no visit",
    "Standardized audit report, exportable",
    "Verification layer over LokOS: replaces nothing, audits everything",
    "Tamil Nadu special audit: Rs 107.94 crore deficiencies (186 BLFs)",
  ]);
  s.addText("Scale: 10.03 crore members | 144.22 lakh savings-linked accounts | 94.16 lakh SHGs on LokOS (sources on slide 8)", {
    x: 0.6, y: 5.12, w: 8.8, h: 0.3, fontFace: MONO, fontSize: 9.5, color: ORANGE, align: "center"
  });
}

// ============ SLIDE 8: RESEARCH AND REFERENCES ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 8);
  header(s, "Research and References");
  panel(s, 0.6, 1.9, 8.8, 2.5);
  s.addText([
    { text: "[1] PIB PRID 2280986 (2026-07-04): LokOS 94.16 lakh SHGs, 10.03 crore members", options: { breakLine: true } },
    { text: "[2] NABARD SHG-Bank linkage stats: 144.22 lakh savings-linked accounts", options: { breakLine: true } },
    { text: "[3] sa-dhan Bharat Microfinance Report FY 2024-25: group counts and flows", options: { breakLine: true } },
    { text: "[4] v5 startup-diligence report, war1v5-ps-17: LokOS, DreamSave, Chomoka, Ensibuuko, Mifos, autopsies, M&A", options: { breakLine: true } },
    { text: "[5] FAILED-STARTUP AUTOPSIES and COMPLAINT MINING verbatim rows in repo docs/RESEARCH.md", options: { breakLine: true } },
  ], { x: 0.95, y: 2.15, w: 8.1, h: 2.0, fontFace: MONO, fontSize: 11.5, color: WHITE, lineSpacing: 17 });
  s.addText("Method: every number labeled VERIFIED or ESTIMATE with source URL + date. AI tooling used and disclosed per rulebook. Full ledger in repo docs/PROOF-LEDGER.md", {
    x: 0.6, y: 4.6, w: 8.8, h: 0.65, fontFace: SANS, fontSize: 10.5, color: MUTED, align: "center"
  });
}

// ============ SLIDE 9: KEY FEATURES (the demo contract) ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.55);
  chrome(s, 9);
  header(s, "What the Demo Proves", "90 seconds, offline, deterministic");
  const feats = [
    { t: "ENTRY", d: "4 icons + voice repeat + green tick. No typing, no literacy barrier." },
    { t: "WITNESS", d: "2 keys sign the meeting root. Receipts are QR/text, member-held." },
    { t: "ATTACK", d: "Simulated tamper rewrites Rs 100 to Rs 10. Chain forks. Receipts fail." },
    { t: "AUDIT", d: "Federation view lists the fork, the event, and which receipts still match." },
  ];
  feats.forEach((f, i) => {
    const x = 0.55 + i * 2.3, w = 2.1;
    panel(s, x, 2.15, w, 2.2);
    s.addText(f.t, { x: x + 0.1, y: 2.3, w: w - 0.2, h: 0.4, fontFace: MONO, fontSize: 13, bold: true, color: ORANGE, align: "center" });
    s.addText(f.d, { x: x + 0.12, y: 2.75, w: w - 0.24, h: 1.5, fontFace: SANS, fontSize: 9.5, color: WHITE, valign: "top", lineSpacing: 12 });
  });
  s.addText("Counter-fact: honest re-entry verifies green. The same receipt is the audit trail.", {
    x: 0.6, y: 4.55, w: 8.8, h: 0.4, fontFace: SANS, fontSize: 11, color: MUTED, align: "center", italic: true
  });
}

// ============ SLIDE 10: THANK YOU ============
{
  const s = pptx.addSlide();
  s.background = { color: BG };
  glow(s, 4.1);
  s.addText("Thank You", { x: 0.5, y: 1.7, w: 9, h: 1.1, fontFace: SERIF, fontSize: 56, bold: true, color: WHITE, align: "center" });
  s.addText("The person who records the money is no longer the only proof.", { x: 0.8, y: 3.0, w: 8.4, h: 0.5, fontFace: SANS, fontSize: 16, color: ORANGE, align: "center", italic: true });
  s.addText("Team 511  |  Track PS-17  |  github.com/harshgounder/craft-n-code-bahi", { x: 0.8, y: 3.6, w: 8.4, h: 0.4, fontFace: MONO, fontSize: 11, color: MUTED, align: "center" });
  s.addText("CRAFT N CODE 2.0  |  ROUND 1  |  2026-08-23", { x: 0.8, y: 4.1, w: 8.4, h: 0.35, fontFace: MONO, fontSize: 9.5, color: MUTED, align: "center" });
}

pptx.writeFile({ fileName: "BAHI-CraftNCode-R1.pptx" }).then(f => console.log("WROTE", f)).catch(e => { console.error("FAIL", e); process.exit(1); });