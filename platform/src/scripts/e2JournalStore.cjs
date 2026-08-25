/**
 * The E2 journal's PHYSICAL layer (duty D7, the frozen storage contract): a
 * single-writer, append-only frame file per pool with a committed-boundary
 * file deciding torn-versus-corrupt. This module owns bytes and durability
 * only; record semantics (the closed schemas, the transition grammar, the
 * read result) live in e2Journal.cjs.
 *
 * THE FILENAME GRAMMAR (an interface correction the document loop folded):
 * `e2-journal-<poolId lowercase hex>.jsonl` in the store's state directory,
 * with the boundary beside it as `e2-journal-<poolId>.boundary`.
 *
 * THE FRAME FORMAT, literal: `length` (u32 big-endian, the byte length of
 * the payload) + the payload (the record's canonical JCS bytes) + the
 * checksum (the FIRST 8 BYTES of SHA-256 over the length prefix and the
 * payload together).
 *
 * THE APPEND TRANSACTION has exactly one commit point: (a) append the frame
 * and fsync the journal file; (b) fsync its directory; (c) write the new
 * boundary content to a temporary file, fsync it, atomically rename it over
 * the boundary file, and fsync the directory. A record is durable, and the
 * action it licenses is permitted, ONLY after (c). The boundary file is the
 * JCS bytes of {"v":1,"kind":"tegara.e2.journal.boundary.v1","poolId":...,
 * "offset":"<canonical decimal>"} followed by the same 8-byte checksum.
 *
 * INITIALIZATION is its own transaction (offset-zero boundary written via
 * temp+rename+dir-fsync BEFORE any frame), and remnants classify
 * exhaustively: no/partial/malformed boundary beside an ABSENT-OR-EMPTY
 * journal -> initialization re-runs fresh; a valid ZERO boundary beside an
 * absent journal -> the empty journal file is created to complete it; a
 * valid NONZERO boundary beside an absent journal -> REFUSES (a journal is
 * never synthesized for a committed nonzero offset). A leftover temporary
 * boundary file is deleted at open; only the final pathname participates in
 * reads.
 *
 * AT READ after initialization: bytes BEYOND the committed offset are the
 * torn final write, truncated before any new append; ANY structural or
 * checksum failure AT OR BEFORE the offset REFUSES the journal outright
 * (discarding a committed record could erase a sent-marker whose send
 * already happened); a missing or malformed boundary beside a NONEMPTY
 * journal refuses; an offset beyond the file length, with a mismatched
 * poolId, or on which frame-walking from zero does not land EXACTLY,
 * refuses. The storage assumption is stated, not proven: data at or before
 * a committed offset is stable, and where it is not, the journal refuses
 * rather than guesses.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const { STATE_DIR } = require("./envStore.cjs");

const POOL_RE = /^[0-9a-f]{64}$/;
const BOUNDARY_KIND = "tegara.e2.journal.boundary.v1";

const refuse = (why) => { throw new Error(`e2JournalStore: ${why}; refusing`); };

const journalPath = (poolId, dir) => {
  if (!POOL_RE.test(poolId)) refuse(`poolId ${JSON.stringify(poolId)} is not 64 lowercase hex`);
  return path.join(dir || STATE_DIR, `e2-journal-${poolId}.jsonl`);
};
const boundaryPath = (poolId, dir) => `${journalPath(poolId, dir)}`.replace(/\.jsonl$/, ".boundary");
const boundaryTmpPath = (poolId, dir) => `${boundaryPath(poolId, dir)}.tmp`;

const checksum8 = (buf) => crypto.createHash("sha256").update(buf).digest().subarray(0, 8);

// ---- frames ----
const encodeFrame = (payloadObj) => {
  const payload = Buffer.from(canonicalString(payloadObj), "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(payload.length, 0);
  return Buffer.concat([len, payload, checksum8(Buffer.concat([len, payload]))]);
};

// walk frames over buf[0..limit); returns { records, offsets } or refuses; a
// walk that cannot land exactly on `limit` refuses (the committed offset must
// be a frame boundary)
const walkFrames = (buf, limit) => {
  const records = [];
  const offsets = [];
  let at = 0;
  while (at < limit) {
    if (at + 4 > limit) refuse(`frame header crosses the committed offset at byte ${at} (corrupt)`);
    const len = buf.readUInt32BE(at);
    const end = at + 4 + len + 8;
    if (end > limit) refuse(`frame at byte ${at} crosses the committed offset (corrupt)`);
    const lenAndPayload = buf.subarray(at, at + 4 + len);
    const sum = buf.subarray(at + 4 + len, end);
    if (!checksum8(lenAndPayload).equals(sum)) refuse(`checksum failure at byte ${at} at or before the committed offset (corrupt)`);
    let obj;
    try { obj = JSON.parse(buf.subarray(at + 4, at + 4 + len).toString("utf8")); }
    catch { refuse(`unparseable committed payload at byte ${at} (corrupt)`); }
    if (canonicalString(obj) !== buf.subarray(at + 4, at + 4 + len).toString("utf8")) {
      refuse(`non-canonical committed payload at byte ${at} (corrupt)`);
    }
    offsets.push(at);
    records.push(obj);
    at = end;
  }
  if (at !== limit) refuse("frame walk does not land exactly on the committed offset");
  return { records, offsets };
};

// ---- the boundary file ----
const encodeBoundary = (poolId, offset) => {
  const body = Buffer.from(canonicalString({
    v: 1, kind: BOUNDARY_KIND, poolId, offset: String(offset),
  }), "utf8");
  return Buffer.concat([body, checksum8(body)]);
};
const parseBoundary = (buf) => {
  if (!buf || buf.length < 9) return null;
  const body = buf.subarray(0, buf.length - 8);
  const sum = buf.subarray(buf.length - 8);
  if (!checksum8(body).equals(sum)) return null;
  let obj;
  try { obj = JSON.parse(body.toString("utf8")); } catch { return null; }
  if (canonicalString(obj) !== body.toString("utf8")) return null;
  if (obj.v !== 1 || obj.kind !== BOUNDARY_KIND) return null;
  // the boundary object is LITERAL: exactly the four members, nothing extra
  // (the D7 checker's finding 9, the looser-than-frozen half)
  if (Object.keys(obj).sort().join(",") !== "kind,offset,poolId,v") return null;
  if (typeof obj.poolId !== "string" || !POOL_RE.test(obj.poolId)) return null;
  if (typeof obj.offset !== "string" || !/^(0|[1-9][0-9]*)$/.test(obj.offset)) return null;
  const off = Number(obj.offset);
  if (!Number.isSafeInteger(off) || off < 0) return null;
  return { poolId: obj.poolId, offset: off };
};

const fsyncFile = (p) => {
  const fd = fs.openSync(p, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
};
const fsyncDir = (p) => {
  const fd = fs.openSync(path.dirname(p), "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
};
const writeBoundaryCommitted = (poolId, offset, dir) => {
  const tmp = boundaryTmpPath(poolId, dir);
  const final = boundaryPath(poolId, dir);
  fs.writeFileSync(tmp, encodeBoundary(poolId, offset));
  fsyncFile(tmp);
  fs.renameSync(tmp, final);
  fsyncDir(final);
};

/**
 * Open (or initialize) the pool's journal. Returns
 * { records, committedOffset, journalFile } after applying the remnant
 * classification and the torn-tail truncation; every refusal path throws.
 */
const openJournal = (poolId, dir) => {
  const jf = journalPath(poolId, dir);
  const bf = boundaryPath(poolId, dir);
  const tmp = boundaryTmpPath(poolId, dir);
  if (fs.existsSync(tmp)) fs.rmSync(tmp); // only the final pathname participates
  const journalExists = fs.existsSync(jf);
  const journalBytes = journalExists ? fs.readFileSync(jf) : Buffer.alloc(0);
  const journalEmpty = journalBytes.length === 0;
  const boundary = fs.existsSync(bf) ? parseBoundary(fs.readFileSync(bf)) : null;

  if (boundary === null) {
    // absent, partial or malformed boundary
    if (!journalExists || journalEmpty) {
      // initialization never committed: re-run it fresh
      writeBoundaryCommitted(poolId, 0, dir);
      if (!journalExists) { fs.writeFileSync(jf, Buffer.alloc(0)); fsyncFile(jf); fsyncDir(jf); }
      return { records: [], committedOffset: 0, journalFile: jf };
    }
    refuse("missing or malformed boundary beside a NONEMPTY journal (corrupt)");
  }
  if (boundary.poolId !== poolId) refuse("the boundary names a different pool");
  if (!journalExists) {
    if (boundary.offset === 0) {
      // the rename committed before the journal file existed: complete initialization
      fs.writeFileSync(jf, Buffer.alloc(0)); fsyncFile(jf); fsyncDir(jf);
      return { records: [], committedOffset: 0, journalFile: jf };
    }
    refuse("a valid NONZERO boundary beside an absent journal (a journal is never synthesized)");
  }
  if (boundary.offset > journalBytes.length) refuse("the committed offset lies beyond the journal file length");
  const { records } = walkFrames(journalBytes, boundary.offset);
  if (journalBytes.length > boundary.offset) {
    // the torn final write: truncated before any new append
    fs.truncateSync(jf, boundary.offset);
    fsyncFile(jf); fsyncDir(jf);
  }
  return { records, committedOffset: boundary.offset, journalFile: jf };
};

/**
 * Append one record through the single-commit-point transaction. The caller
 * passes the state from openJournal (or a prior append); returns the new
 * committed offset. The record becomes durable, and the action it licenses
 * permitted, only when this function RETURNS.
 */
const appendRecord = (poolId, committedOffset, payloadObj, dir) => {
  const jf = journalPath(poolId, dir);
  const frame = encodeFrame(payloadObj);
  const fd = fs.openSync(jf, "a");
  try {
    const at = fs.fstatSync(fd).size;
    if (at !== committedOffset) {
      refuse(`the journal file length ${at} disagrees with the committed offset ${committedOffset} at append ` +
        "(another writer, or an uncommitted tail the caller did not open through openJournal)");
    }
    // write the COMPLETE frame: writeSync may return a short count, and a
    // short write that then commits the full offset poisons the store (the
    // D7 checker's critical finding 1, reproduced by injection); loop until
    // every byte lands or refuse before any fsync or boundary movement
    let written = 0;
    while (written < frame.length) {
      const n = fs.writeSync(fd, frame, written, frame.length - written);
      if (!Number.isInteger(n) || n <= 0) {
        refuse(`the frame write stalled at byte ${written} of ${frame.length}; nothing was committed`);
      }
      written += n;
    }
    fs.fsyncSync(fd); // (a)
  } finally { fs.closeSync(fd); }
  fsyncDir(jf); // (b)
  const next = committedOffset + frame.length;
  writeBoundaryCommitted(poolId, next, dir); // (c), the commit point
  return next;
};

module.exports = {
  journalPath, boundaryPath, encodeFrame, walkFrames, encodeBoundary, parseBoundary,
  openJournal, appendRecord, BOUNDARY_KIND,
};
