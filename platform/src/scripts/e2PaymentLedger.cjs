/**
 * ONE APPEND-ONLY EVENT LOG for the payment demonstrations, and the decoder that says what a
 * payment IS.
 *
 * WHY ONE LOG RATHER THAN TWO RECORDS, which is the point of this module's second version. There
 * used to be a ledger of what left the machine and, beside it, a record of what the child process
 * did. The child wrote both, and beside each declaration it also wrote ITS OWN COUNT of what the
 * ledger held at that moment. A confirmation round falsified those counts and watched the
 * completeness properties accept a declaration that truthful counts reject. The count was a number
 * the judged party computed about itself.
 *
 * SO THE COUNT IS GONE AND ORDER REPLACES IT. Payments and declarations are events in ONE log, in
 * the order they happened, so a declaration's POSITION is its moment and what had been paid by
 * then is the transfer events BEFORE it. `paidCountsBefore` derives that from the log's order.
 * There is no snapshot left to falsify, because there is no snapshot: a child wanting to lie would
 * have to write payment events out of order, which is a different and far more visible defect, and
 * every payment event's contents are already derived from its bytes.
 *
 * WHAT THE READER MUST NOT DO, and did until an independent round defeated it four ways. IT MUST
 * NOT TRUST A STORED CLASSIFICATION. A line whose bytes encode one obligation and whose stored
 * field names another is a REFUSAL rather than a count on either side, since silently preferring
 * one side would be the same defect with a different winner. A send whose bytes match nothing the
 * harness declares is UNRECOGNIZED rather than absorbed into a catch-all that nothing could fall
 * outside. And the hexadecimal decode validates the WHOLE input, because the truncating version
 * accepted a valid transfer with a stray tail appended as that transfer.
 *
 * WHAT THE ENVELOPE CARRIES, and why the recipient is in it. A tag, the accrual identifier, the
 * RECIPIENT identifier, then the amount as digits. The earlier envelope ignored the recipient the
 * writer passes, so two obligations differing only in who is paid encoded identically and a
 * recipient error could not be observed here at all.
 *
 * WHAT IT IS NOT. This is a HARNESS encoding, declared here and used only by the demonstrations.
 * It is not the product's transition format. The log stands in for the chain plus a flight
 * recorder: it is written before the process can end, never read by the code under test, and never
 * derived from the journal.
 */
const fs = require("fs");

const refuse = (m) => { throw new Error(`e2PaymentLedger: ${m}`); };

const TRANSFER_TAG = "0a0b";
const ID_HEX_LEN = 64;
const HEX64 = /^[0-9a-f]{64}$/;
/** whole-input validation: an even number of hexadecimal digits and nothing else. */
const WHOLE_HEX = /^([0-9a-f]{2})*$/;

/** the event kinds this log carries. A line naming anything else is a refusal, so a typo cannot
 *  become an event class every reader silently ignores. */
const KINDS = Object.freeze(["send", "cut", "declares-complete", "step", "final", "error"]);

/** bytes to lowercase hex, whatever spelling they arrived in. A Buffer and a mixed-case string
 *  naming the same transfer must answer the same, which is the defect this exists for. */
const hexOf = (b) => (Buffer.isBuffer(b) ? b.toString("hex") : String(b)).toLowerCase();

const encodeTransfer = (accrualId, recipientId, amountCredits) => {
  if (typeof accrualId !== "string" || !HEX64.test(accrualId)) {
    refuse(`encodeTransfer needs the accrual identifier as ${ID_HEX_LEN} lowercase hex, and got ${JSON.stringify(accrualId)}`);
  }
  if (typeof recipientId !== "string" || !HEX64.test(recipientId)) {
    refuse(`encodeTransfer needs the recipient identifier as ${ID_HEX_LEN} lowercase hex, and got ${JSON.stringify(recipientId)}`);
  }
  if (!/^[0-9]+$/.test(String(amountCredits))) {
    refuse(`encodeTransfer needs the amount as digits, and got ${JSON.stringify(amountCredits)}`);
  }
  return TRANSFER_TAG + accrualId + recipientId
    + Buffer.from(String(amountCredits), "utf8").toString("hex");
};

/** the inverse, and the only thing that decides whether something was a payment. Anything that
 *  does not decode is NOT reported as a transfer, which is what keeps a reservation or a header
 *  out of the payment count. */
const decodeTransfer = (bytes) => {
  const hex = hexOf(bytes);
  if (!WHOLE_HEX.test(hex)) return null;            // a malformed tail is not a valid transfer
  const head = TRANSFER_TAG.length;
  const want = head + ID_HEX_LEN * 2;
  if (!hex.startsWith(TRANSFER_TAG) || hex.length <= want) return null;
  const accrualId = hex.slice(head, head + ID_HEX_LEN);
  const recipientId = hex.slice(head + ID_HEX_LEN, want);
  let amountCredits;
  try { amountCredits = Buffer.from(hex.slice(want), "hex").toString("utf8"); } catch { return null; }
  if (!/^[0-9]+$/.test(amountCredits)) return null;
  return { accrualId, recipientId, amountCredits };
};

/**
 * makeEventLog(path, { otherShapes })
 *
 * ONE LINE PER EVENT, appended and FSYNCED before the caller returns, because the process it is
 * recording may end in the next statement. An event written but not flushed is a payment this log
 * would deny ever happened.
 *
 * `otherShapes` DECLARES THE NON-PAYMENT TRANSITIONS THIS HARNESS BUILDS, as `{name: tagHex}`.
 * Without it there is no such thing as an unrecognized send, because every undecodable byte string
 * falls into one catch-all class and the provenance question answers itself.
 */
const makeEventLog = (logPath, opts = {}) => {
  if (typeof logPath !== "string" || !logPath) refuse("makeEventLog needs the log path");
  const otherShapes = opts.otherShapes || {};
  for (const [name, tag] of Object.entries(otherShapes)) {
    if (typeof tag !== "string" || !/^([0-9a-f]{2})+$/.test(tag)) {
      refuse(`otherShapes.${name} must be a lowercase hex tag, and is ${JSON.stringify(tag)}`);
    }
    if (tag === TRANSFER_TAG) refuse(`otherShapes.${name} uses the transfer tag, which would make a payment unrecognizable as one`);
  }

  /** WHAT A SEND ACTUALLY WAS, decided from its bytes and from nothing else. */
  const shapeOf = (bytes) => {
    const decoded = decodeTransfer(bytes);
    if (decoded) return { what: "credit-transfer", ...decoded };
    const hex = hexOf(bytes);
    if (WHOLE_HEX.test(hex)) {
      for (const [name, tag] of Object.entries(otherShapes)) {
        if (hex.startsWith(tag)) return { what: "other-transition", shape: name };
      }
    }
    // NOT absorbed into the catch-all. A send whose bytes match nothing this harness builds is
    // the thing a provenance assertion exists to notice.
    return { what: "unrecognized" };
  };

  const record = (entry) => {
    const fd = fs.openSync(logPath, "a");
    try {
      fs.writeSync(fd, JSON.stringify(entry) + "\n");
      fs.fsyncSync(fd); // it must survive the process ending in the next statement
    } finally { fs.closeSync(fd); }
  };

  /** the raw lines. A malformed line is a REFUSAL rather than a skip: a log that quietly dropped
   *  a line it could not parse would under-count payments, which is the direction that reads as
   *  safe and is not. */
  const rawLines = () => {
    if (!fs.existsSync(logPath)) return [];
    return fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean).map((line, i) => {
      try { return JSON.parse(line); }
      catch { return refuse(`line ${i + 1} of the event log is not readable; refusing rather than counting one payment fewer`); }
    });
  };

  /**
   * EVERY EVENT IN ORDER, each carrying its own POSITION, and every send re-decided from its bytes
   * with the stored fields checked against that answer rather than believed. The position is what
   * makes a declaration's moment readable without anybody reporting a count.
   */
  const events = () => rawLines().map((e, i) => {
    const at = `line ${i + 1}`;
    if (!e || typeof e !== "object" || Array.isArray(e)) refuse(`${at} is not an object`);
    if (!KINDS.includes(e.kind)) refuse(`${at} names kind ${JSON.stringify(e.kind)}, which is not one of ${KINDS.join(", ")}`);
    if (e.kind !== "send") return { ...e, seq: i };
    if (typeof e.bytes !== "string") refuse(`${at} is a send carrying no bytes, so what left cannot be established from it`);
    const truth = shapeOf(e.bytes);
    if (e.what !== undefined && e.what !== truth.what) {
      refuse(`${at} is stored as ${JSON.stringify(e.what)} and its bytes are ${truth.what}; refusing rather than choosing one`);
    }
    if (e.shape !== undefined && e.shape !== truth.shape) {
      refuse(`${at} is stored as shape ${JSON.stringify(e.shape)} and its bytes are ${JSON.stringify(truth.shape === undefined ? null : truth.shape)}; refusing rather than choosing one`);
    }
    if (truth.what === "credit-transfer") {
      if (e.accrualId !== undefined && e.accrualId !== truth.accrualId) {
        refuse(`${at} names accrual ${String(e.accrualId).slice(0, 12)} and its bytes carry ${truth.accrualId.slice(0, 12)}; refusing rather than choosing one`);
      }
      if (e.recipientId !== undefined && e.recipientId !== truth.recipientId) {
        refuse(`${at} names recipient ${String(e.recipientId).slice(0, 12)} and its bytes carry ${truth.recipientId.slice(0, 12)}; refusing rather than choosing one`);
      }
      if (e.amountCredits !== undefined && String(e.amountCredits) !== truth.amountCredits) {
        refuse(`${at} names amount ${e.amountCredits} and its bytes carry ${truth.amountCredits}; refusing rather than choosing one`);
      }
    }
    return { ...e, ...truth, seq: i };
  });

  const transfers = () => events().filter((e) => e.kind === "send" && e.what === "credit-transfer");
  const transfersFor = (accrualId) => transfers().filter((e) => e.accrualId === accrualId);
  const unrecognized = () => events().filter((e) => e.kind === "send" && e.what === "unrecognized");

  /**
   * WHAT HAD BEEN PAID, PER ACCRUAL, BEFORE POSITION `seq`. This replaces the count a child used
   * to compute about itself. The answer is a property of the log's ORDER, and the position comes
   * from the log rather than from anybody's report.
   */
  const paidCountsBefore = (seq) => {
    if (!Number.isInteger(seq) || seq < 0) refuse(`paidCountsBefore needs a non-negative position, and got ${JSON.stringify(seq)}`);
    const counts = {};
    for (const t of transfers()) {
      if (t.seq >= seq) break;                       // events() is in order, so this is total
      counts[t.accrualId] = (counts[t.accrualId] || 0) + 1;
    }
    return counts;
  };

  const clear = () => fs.rmSync(logPath, { force: true });

  /** THE ADAPTER'S OWN SEND EVENT, built from the bytes rather than from what the caller believes
   *  it is sending. The caller hands over exactly what went to the transport. */
  const entryForSend = (hash, bytes) => ({ kind: "send", ...shapeOf(bytes),
    hash, bytes: hexOf(bytes), pid: process.pid, at: new Date().toISOString() });

  return { path: logPath, record, events, transfers, transfersFor, unrecognized,
    paidCountsBefore, clear, entryForSend, shapeOf, length: () => rawLines().length };
};

module.exports = { TRANSFER_TAG, ID_HEX_LEN, KINDS, hexOf, encodeTransfer, decodeTransfer,
  makeEventLog };
