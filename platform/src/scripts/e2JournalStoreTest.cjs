/**
 * Offline test for the journal's physical layer (plain `node`, no network),
 * driving the playbook's interruption matrix against the frozen storage
 * contract: every remnant class at initialization, a crash between EVERY pair
 * of durable actions in the append transaction (simulated by performing the
 * earlier actions' file effects and not the later ones), the torn-tail
 * truncation including the full-frame-before-commit row, the
 * corrupt-at-or-before-offset hard stop, the next append after each recovery,
 * and the refusal rows (nonzero boundary with no journal, foreign poolId,
 * offset beyond length, non-frame-aligned offset). Expected bytes are
 * recomputed from the contract's own formulas, never from the code under
 * test's output on the same input being asserted.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const {
  journalPath, boundaryPath, encodeFrame, encodeBoundary, parseBoundary,
  openJournal, appendRecord,
} = require("./e2JournalStore.cjs");
const { canonicalString } = require("./canonicalJson.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => {
  if (cond) { passed++; }
  else { failed++; console.error("FAIL:", name); }
};
const throws = (name, fn, re) => {
  try { fn(); failed++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || String(e))); }
};

const POOL = "ab".repeat(32);
const rec = (n) => ({ v: 1, kind: "probe", object: "pool", gen: 1, poolId: POOL, n });
const freshDir = () => fs.mkdtempSync(path.join(os.tmpdir(), "tegara-e2js-"));

// ---- the frame codec against the contract's own formula ----
{
  const payload = Buffer.from(canonicalString(rec(1)), "utf8");
  const len = Buffer.alloc(4); len.writeUInt32BE(payload.length, 0);
  const expectSum = crypto.createHash("sha256").update(Buffer.concat([len, payload])).digest().subarray(0, 8);
  const frame = encodeFrame(rec(1));
  ok("frame is length + JCS payload + 8-byte truncated sha256 over both",
    frame.equals(Buffer.concat([len, payload, expectSum])));
}
{
  const body = Buffer.from(canonicalString({ v: 1, kind: "tegara.e2.journal.boundary.v1", poolId: POOL, offset: "17" }), "utf8");
  const sum = crypto.createHash("sha256").update(body).digest().subarray(0, 8);
  ok("boundary bytes match the literal formula", encodeBoundary(POOL, 17).equals(Buffer.concat([body, sum])));
  ok("a valid boundary parses back", parseBoundary(encodeBoundary(POOL, 17)).offset === 17);
  ok("a flipped boundary byte parses to null", parseBoundary(Buffer.concat([body, Buffer.from(sum).fill(0)])) === null);
}

// ---- initialization remnants, exhaustively ----
{
  const d = freshDir();
  const r = openJournal(POOL, d);
  ok("fresh open initializes to offset zero, no records", r.committedOffset === 0 && r.records.length === 0);
  ok("the boundary file exists after initialization", parseBoundary(fs.readFileSync(boundaryPath(POOL, d))).offset === 0);
}
{
  const d = freshDir(); // partial boundary beside an ABSENT journal: re-run fresh
  fs.writeFileSync(boundaryPath(POOL, d), Buffer.from("garbage"));
  const r = openJournal(POOL, d);
  ok("a malformed boundary beside an absent journal re-initializes", r.committedOffset === 0);
}
{
  const d = freshDir(); // malformed boundary beside an EMPTY journal: re-run fresh
  fs.writeFileSync(journalPath(POOL, d), Buffer.alloc(0));
  fs.writeFileSync(boundaryPath(POOL, d), Buffer.from("garbage"));
  ok("a malformed boundary beside an empty journal re-initializes", openJournal(POOL, d).committedOffset === 0);
}
{
  const d = freshDir(); // valid ZERO boundary, absent journal: the rename won, complete it
  fs.writeFileSync(boundaryPath(POOL, d), encodeBoundary(POOL, 0));
  const r = openJournal(POOL, d);
  ok("a zero boundary with no journal completes initialization", r.committedOffset === 0 && fs.existsSync(journalPath(POOL, d)));
}
{
  const d = freshDir(); // valid NONZERO boundary, absent journal: refused
  fs.writeFileSync(boundaryPath(POOL, d), encodeBoundary(POOL, 40));
  throws("a nonzero boundary with no journal refuses", () => openJournal(POOL, d), /never synthesized/);
}
{
  const d = freshDir(); // a leftover TEMPORARY boundary is deleted at open
  fs.writeFileSync(boundaryPath(POOL, d) + ".tmp", Buffer.from("leftover"));
  openJournal(POOL, d);
  ok("a leftover temporary boundary file is deleted at open", !fs.existsSync(boundaryPath(POOL, d) + ".tmp"));
}
{
  const d = freshDir(); // malformed boundary beside a NONEMPTY journal: hard stop
  openJournal(POOL, d);
  appendRecord(POOL, 0, rec(1), d);
  fs.writeFileSync(boundaryPath(POOL, d), Buffer.from("garbage"));
  throws("a malformed boundary beside a nonempty journal refuses", () => openJournal(POOL, d), /NONEMPTY journal/);
}

// ---- the append transaction's crash points, one per pair of durable actions ----
// The simulated crash performs the earlier actions' file effects and stops.
{
  // crash AFTER (a) frame appended, BEFORE (c) boundary rename: the frame is
  // the torn final write, truncated at next open, and a fresh append lands
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  fs.appendFileSync(journalPath(POOL, d), encodeFrame(rec(2))); // (a) happened, (c) did not
  const r = openJournal(POOL, d);
  ok("a full frame beyond the boundary is truncated as the torn tail",
    r.records.length === 1 && r.records[0].n === 1 && r.committedOffset === off);
  ok("the file was physically truncated to the committed offset",
    fs.statSync(journalPath(POOL, d)).size === off);
  const off2 = appendRecord(POOL, r.committedOffset, rec(3), d);
  const r2 = openJournal(POOL, d);
  ok("the first later append lands cleanly after truncation (the row-9 case)",
    r2.records.length === 2 && r2.records[1].n === 3 && r2.committedOffset === off2);
}
{
  // crash MID-FRAME (partial bytes beyond the boundary): torn, truncated
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  fs.appendFileSync(journalPath(POOL, d), encodeFrame(rec(2)).subarray(0, 7));
  const r = openJournal(POOL, d);
  ok("partial frame bytes beyond the boundary are truncated", r.records.length === 1 && r.committedOffset === off);
}
{
  // crash between boundary TEMP write and RENAME: the temp is deleted, the
  // old boundary stands, the appended frame is torn tail
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  const frame2 = encodeFrame(rec(2));
  fs.appendFileSync(journalPath(POOL, d), frame2);
  fs.writeFileSync(boundaryPath(POOL, d) + ".tmp", encodeBoundary(POOL, off + frame2.length));
  const r = openJournal(POOL, d);
  ok("a crash before the boundary rename leaves the old commit standing",
    r.committedOffset === off && r.records.length === 1);
  ok("the stale temp boundary was removed", !fs.existsSync(boundaryPath(POOL, d) + ".tmp"));
}

// ---- corrupt at or before the offset: hard stop, never truncation ----
{
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  appendRecord(POOL, off, rec(2), d);
  const bytes = fs.readFileSync(journalPath(POOL, d));
  bytes[6] = bytes[6] ^ 0xff; // inside the first committed frame's payload
  fs.writeFileSync(journalPath(POOL, d), bytes);
  throws("a corrupt committed frame refuses the journal outright", () => openJournal(POOL, d), /corrupt/);
}
{
  // an upward-corrupted length field in a COMMITTED frame is caught by the
  // boundary (the frame crosses the offset), never trusted
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  appendRecord(POOL, off, rec(1), d);
  const bytes = fs.readFileSync(journalPath(POOL, d));
  bytes.writeUInt32BE(60000, 0);
  fs.writeFileSync(journalPath(POOL, d), bytes);
  throws("an upward-corrupted committed length crosses the offset and refuses",
    () => openJournal(POOL, d), /crosses the committed offset|checksum/);
}

// ---- the boundary refusal rows ----
{
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  fs.writeFileSync(boundaryPath(POOL, d), encodeBoundary(POOL, off + 999));
  throws("an offset beyond the file length refuses", () => openJournal(POOL, d), /beyond the journal file length/);
  fs.writeFileSync(boundaryPath(POOL, d), encodeBoundary(POOL, off - 1));
  throws("a non-frame-aligned offset refuses", () => openJournal(POOL, d), /crosses the committed offset|land exactly|corrupt/);
  fs.writeFileSync(boundaryPath(POOL, d), encodeBoundary("cd".repeat(32), off));
  throws("a boundary naming a different pool refuses", () => openJournal(POOL, d), /different pool/);
}

// ---- two concurrent first writers: the second append sees the moved length ----
{
  const d = freshDir();
  const off0 = openJournal(POOL, d).committedOffset;
  const off1 = appendRecord(POOL, off0, rec(1), d);
  ok("the second writer's stale-offset append refuses rather than interleaving",
    (() => { try { appendRecord(POOL, off0, rec(9), d); return false; } catch (e) { return /disagrees with the committed offset/.test(e.message); } })());
  ok("the first writer's committed record is intact", openJournal(POOL, d).records.length === 1 && openJournal(POOL, d).committedOffset === off1);
}

// ---- non-canonical committed payloads refuse (the canonical-form gate) ----
{
  const d = freshDir();
  openJournal(POOL, d);
  const payload = Buffer.from('{"b":1,"a":2}', "utf8"); // parseable, NOT canonical order
  const len = Buffer.alloc(4); len.writeUInt32BE(payload.length, 0);
  const sum = crypto.createHash("sha256").update(Buffer.concat([len, payload])).digest().subarray(0, 8);
  const frame = Buffer.concat([len, payload, sum]);
  fs.appendFileSync(journalPath(POOL, d), frame);
  fs.writeFileSync(boundaryPath(POOL, d), encodeBoundary(POOL, frame.length));
  throws("a committed non-canonical payload refuses", () => openJournal(POOL, d), /non-canonical/);
}

// ---- FAULT INJECTION pins the commit-point ORDER (unobservable after a
// successful append): a crash in EITHER half of the transaction must leave
// the store recoverable at the OLD commit. Under a boundary-first mutation,
// a failing frame write leaves a nonzero boundary beside a short journal,
// which the offset-beyond-length rule then refuses forever; these cases are
// what make that mutation die. fs is the shared module object, so the test
// injects by patching one call and restoring in finally. ----
{
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  const realRename = fs.renameSync;
  fs.renameSync = () => { throw new Error("injected: crash before the boundary rename"); };
  let threw = false;
  try { appendRecord(POOL, off, rec(2), d); } catch { threw = true; }
  finally { fs.renameSync = realRename; }
  ok("a rename-half crash surfaces to the caller", threw);
  const r = openJournal(POOL, d);
  ok("after a rename-half crash the store recovers at the OLD commit",
    r.committedOffset === off && r.records.length === 1);
  ok("a fresh append then lands", openJournal(POOL, d).committedOffset === off
    && (() => { const o2 = appendRecord(POOL, off, rec(3), d); return openJournal(POOL, d).committedOffset === o2; })());
}
{
  const d = freshDir();
  let off = openJournal(POOL, d).committedOffset;
  off = appendRecord(POOL, off, rec(1), d);
  const realWrite = fs.writeSync;
  fs.writeSync = () => { throw new Error("injected: crash during the frame write"); };
  let threw = false;
  try { appendRecord(POOL, off, rec(2), d); } catch { threw = true; }
  finally { fs.writeSync = realWrite; }
  ok("a frame-write crash surfaces to the caller", threw);
  const r = openJournal(POOL, d);
  ok("after a frame-write crash the store recovers at the OLD commit (order pinned)",
    r.committedOffset === off && r.records.length === 1);
}

// ---- the boundary object is LITERAL: a well-checksummed boundary with an
// extra member is malformed, not a boundary (the D7 checker's finding 9) ----
{
  const body = Buffer.from(canonicalString({
    v: 1, kind: "tegara.e2.journal.boundary.v1", poolId: POOL, offset: "0", note: "x",
  }), "utf8");
  const sum = crypto.createHash("sha256").update(body).digest().subarray(0, 8);
  ok("a boundary carrying an extra member parses to null despite a valid checksum",
    parseBoundary(Buffer.concat([body, sum])) === null);
}

// ---- SHORT WRITES: writeSync is allowed to return fewer bytes than asked,
// and the append must still land the COMPLETE frame before moving the
// boundary (the D7 checker's critical finding 1). Injection caps the byte
// count per call at the beginning (1 byte per call), the middle, and one
// short of the final byte; each variant must produce a journal whose reread
// round-trips the record intact. ----
{
  const frameLen = encodeFrame(rec(1)).length;
  for (const [label, cap] of [["one byte per call", 1],
    ["a mid-frame split", Math.floor(frameLen / 2)],
    ["short at the final byte", frameLen - 1]]) {
    const d = freshDir();
    let off = openJournal(POOL, d).committedOffset;
    const realWrite = fs.writeSync;
    let calls = 0;
    fs.writeSync = (fd, buf, o, len) => { calls++; return realWrite(fd, buf, o, Math.min(len, cap)); };
    try { off = appendRecord(POOL, off, rec(1), d); }
    finally { fs.writeSync = realWrite; }
    const r = openJournal(POOL, d);
    ok(`short writes (${label}) still commit the complete frame`,
      calls > 1 && r.committedOffset === off && r.records.length === 1
      && canonicalString(r.records[0]) === canonicalString(rec(1)));
  }
}
{
  // a write that stalls at zero bytes refuses BEFORE any boundary movement
  const d = freshDir();
  const off = openJournal(POOL, d).committedOffset;
  const realWrite = fs.writeSync;
  fs.writeSync = () => 0;
  let threw = false;
  try { appendRecord(POOL, off, rec(1), d); } catch (e) { threw = /stalled/.test(e.message); }
  finally { fs.writeSync = realWrite; }
  const r = openJournal(POOL, d);
  ok("a zero-byte write stall refuses and commits nothing",
    threw && r.committedOffset === off && r.records.length === 0);
}

console.log(`e2JournalStoreTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
