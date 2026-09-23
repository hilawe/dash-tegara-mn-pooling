/**
 * e2PaymentLedgerTest: the offline battery for the payment demonstrations' shared ORACLE.
 *
 * WHY THIS BATTERY EXISTS AT ALL. Two demonstrations are judged by this decoder. If it is wrong,
 * both are green and wrong together, and neither can notice, because each one's evidence is read
 * back through this same code.
 *
 * THE FIRST VERSION OF THIS BATTERY COULD NOT SEE ITS OWN ORACLE MOVE, which an independent round
 * demonstrated by executing it. Every valid vector was produced by calling the ENCODER UNDER
 * TEST, so a mutation that encoded `amount + 1` while decoding `amount - 1` passed all 27
 * assertions with 1188001 physically in the bytes and 1188000 reported. Complementing the
 * identifier bytes in both directions passed as well. An expectation obtained from the artifact
 * it judges is the class this project keeps meeting, and this is its form here.
 *
 * SO THE CANONICAL VECTORS BELOW ARE WRITTEN BY HAND, digit by digit, and the encoder is required
 * to reproduce them. Their construction is stated in a comment so a later reader can rebuild them
 * with a pencil rather than by running the code they check.
 *
 * WHAT IT BINDS:
 *   1. the hand-written vectors: the encoder produces exactly those bytes and the decoder reads
 *      exactly those fields back out of them, so neither can move without failing;
 *   2. THE SAME TRANSFER IN A DIFFERENT SPELLING DECODES THE SAME (uppercase, a Buffer, mixed);
 *   3. what is NOT a payment, including a malformed tail, which the truncating decode this
 *      replaces accepted as the valid prefix;
 *   4. the encoder REFUSES malformed inputs rather than producing bytes that decode to something
 *      else;
 *   5. THE READER DECIDES FROM BYTES AND NEVER FROM A STORED FIELD. A line whose stored
 *      classification, accrual, recipient or amount contradicts its bytes REFUSES, a send whose
 *      bytes match nothing the harness declares is UNRECOGNIZED rather than absorbed, and a
 *      re-sent transfer counts twice however it is spelled.
 */
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const L = require("./e2PaymentLedger.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed += 1; console.log(`  PASS: ${name}`); } else { failed += 1; console.log(`  FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); failed += 1; console.log(`  FAIL: ${name} (no refusal)`); }
  catch (e) { const m = (e && e.message) || String(e); ok(`${name} (${m.slice(0, 70)})`, re.test(m)); }
};

const ACC_A = "a1".repeat(32);
const ACC_B = "b2".repeat(32);
const REC_A = "71".repeat(32);
const REC_B = "72".repeat(32);

/**
 * ---- THE CANONICAL VECTORS, WRITTEN BY HAND ----
 *
 * Each one is the tag `0a0b`, then the 32-byte accrual identifier, then the 32-byte recipient
 * identifier, then the decimal amount as ASCII in hexadecimal. The amounts here are the two the
 * multi-epoch demonstration's first epoch owes, and their ASCII is spelled out below so the
 * vector can be checked without running anything:
 *
 *   "1188000" -> 31 31 38 38 30 30 30
 *   "792000"  -> 37 39 32 30 30 30
 *   "10"      -> 31 30
 *
 * NOTHING IN THIS BLOCK CALLS THE ENCODER. That is the whole point of it.
 */
const VECTORS = [
  { name: "epoch 5's first obligation",
    bytes: "0a0b" + "a1".repeat(32) + "71".repeat(32) + "31313838303030",
    accrualId: ACC_A, recipientId: REC_A, amountCredits: "1188000" },
  { name: "epoch 5's second obligation",
    bytes: "0a0b" + "b2".repeat(32) + "72".repeat(32) + "373932303030",
    accrualId: ACC_B, recipientId: REC_B, amountCredits: "792000" },
  { name: "a small amount, to fix the digit encoding at two characters",
    bytes: "0a0b" + "a1".repeat(32) + "72".repeat(32) + "3130",
    accrualId: ACC_A, recipientId: REC_B, amountCredits: "10" },
];

const main = () => {
  console.log("e2PaymentLedgerTest");

  // ---- 1. the hand-written vectors, in both directions ----
  for (const v of VECTORS) {
    ok(`the encoder reproduces the hand-written bytes for ${v.name}`,
      L.encodeTransfer(v.accrualId, v.recipientId, v.amountCredits) === v.bytes);
    const d = L.decodeTransfer(v.bytes);
    ok(`the decoder reads the accrual out of the hand-written bytes for ${v.name}`,
      d && d.accrualId === v.accrualId);
    ok(`the decoder reads the recipient out of the hand-written bytes for ${v.name}`,
      d && d.recipientId === v.recipientId);
    ok(`the decoder reads the amount out of the hand-written bytes for ${v.name}`,
      d && d.amountCredits === v.amountCredits);
  }
  // THE RECIPIENT IS PHYSICALLY IN THE ENVELOPE, which is what makes a recipient error
  // observable at all. The earlier envelope ignored it and two obligations differing only in
  // who is paid produced identical bytes.
  ok("two obligations differing ONLY in recipient encode to different bytes",
    L.encodeTransfer(ACC_A, REC_A, "10") !== L.encodeTransfer(ACC_A, REC_B, "10"));
  ok("two obligations differing only in accrual encode to different bytes",
    L.encodeTransfer(ACC_A, REC_A, "10") !== L.encodeTransfer(ACC_B, REC_A, "10"));
  ok("two obligations differing only in amount encode to different bytes",
    L.encodeTransfer(ACC_A, REC_A, "10") !== L.encodeTransfer(ACC_A, REC_A, "11"));

  // ---- 2. THE SPELLINGS ----
  {
    const v = VECTORS[1];
    const spellings = { "uppercase hex": v.bytes.toUpperCase(),
      "a Buffer": Buffer.from(v.bytes, "hex"),
      "mixed case": v.bytes.slice(0, 20).toUpperCase() + v.bytes.slice(20) };
    for (const [how, x] of Object.entries(spellings)) {
      const d = L.decodeTransfer(x);
      ok(`the same transfer sent as ${how} decodes to the same payment`,
        d && d.accrualId === v.accrualId && d.recipientId === v.recipientId
        && d.amountCredits === v.amountCredits);
    }
  }

  // ---- 3. what is NOT a payment ----
  {
    ok("a reservation transition (a different tag) is not a transfer",
      L.decodeTransfer("0c0d" + ACC_A) === null);
    ok("a header transition is not a transfer", L.decodeTransfer("010200050 1".replace(" ", "")) === null);
    ok("bytes too short to carry both identifiers are not a transfer",
      L.decodeTransfer(L.TRANSFER_TAG + ACC_A + "71".repeat(10)) === null);
    ok("a transfer envelope with no amount at all is not a transfer",
      L.decodeTransfer(L.TRANSFER_TAG + ACC_A + REC_A) === null);
    ok("a transfer envelope whose amount is not digits is not a transfer",
      L.decodeTransfer(L.TRANSFER_TAG + ACC_A + REC_A
        + Buffer.from("not-a-number", "utf8").toString("hex")) === null);
    // THE MALFORMED TAIL, which the truncating decode accepted as the valid prefix
    ok("a valid transfer with a stray hexadecimal digit appended is NOT that transfer",
      L.decodeTransfer(VECTORS[2].bytes + "0") === null);
    ok("a valid transfer with a non-hexadecimal tail appended is NOT that transfer",
      L.decodeTransfer(VECTORS[2].bytes + "zz") === null);
  }

  // ---- 4. the encoder refuses rather than mis-encoding ----
  {
    throws("the encoder refuses an accrual that is not 64 hex",
      () => L.encodeTransfer("a1", REC_A, "100"), /accrual identifier/);
    throws("the encoder refuses an uppercase accrual, which would decode to a different string",
      () => L.encodeTransfer(ACC_A.toUpperCase(), REC_A, "100"), /accrual identifier/);
    throws("the encoder refuses a recipient that is not 64 hex",
      () => L.encodeTransfer(ACC_A, "71", "100"), /recipient identifier/);
    throws("the encoder refuses an amount that is not digits",
      () => L.encodeTransfer(ACC_A, REC_A, "12.5"), /amount as digits/);
    throws("the encoder refuses a negative amount",
      () => L.encodeTransfer(ACC_A, REC_A, "-1"), /amount as digits/);
  }

  // ---- 5. THE READER DECIDES FROM BYTES, never from a stored field ----
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-ledger-test-"));
    const led = L.makeEventLog(path.join(dir, "external-effects.jsonl"),
      { otherShapes: { reservation: "0c0d", header: "0102" } });
    ok("an absent ledger reads as no effects at all", led.events().length === 0);

    led.record(led.entryForSend("h1", VECTORS[0].bytes));
    led.record(led.entryForSend("h2", "0c0d" + ACC_B));                 // a reservation
    led.record(led.entryForSend("h3", VECTORS[1].bytes));
    led.record(led.entryForSend("h4", Buffer.from(VECTORS[0].bytes, "hex")));

    ok("the ledger holds every send, payment or not", led.events().length === 4);
    ok("THE SAME TRANSFER RE-SENT AS A BUFFER COUNTS AS A SECOND PAYMENT FOR THAT ACCRUAL",
      led.transfersFor(ACC_A).length === 2);
    ok("the other accrual is counted separately", led.transfersFor(ACC_B).length === 1);
    ok("a declared non-payment shape is not counted as a payment", led.transfers().length === 3);
    ok("a declared non-payment shape is not unrecognized either", led.unrecognized().length === 0);
    ok("every payment's amount comes from its bytes",
      led.transfersFor(ACC_B)[0].amountCredits === "792000");
    ok("every payment's recipient comes from its bytes",
      led.transfersFor(ACC_B)[0].recipientId === REC_B);

    // AN UNDECODABLE SEND IS UNRECOGNIZED, not absorbed into the catch-all. Before this fold
    // every such send became "other-transition" and the provenance assertion could not fail.
    led.record(led.entryForSend("junk", "deadbeef"));
    ok("a send whose bytes match nothing the harness declares is UNRECOGNIZED",
      led.unrecognized().length === 1);
    ok("that send is still not counted as a payment", led.transfers().length === 3);
    led.clear();

    // A STORED FIELD THAT CONTRADICTS THE BYTES REFUSES. Each of these is a plain object the
    // supported `record` method accepts, which is how the round defeated the first reader.
    const contradictions = [
      ["classification", { ...led.entryForSend("h", VECTORS[0].bytes), what: "other-transition" }, /stored as .* and its bytes are/],
      ["accrual", { ...led.entryForSend("h", VECTORS[0].bytes), accrualId: ACC_B }, /names accrual .* and its bytes carry/],
      ["recipient", { ...led.entryForSend("h", VECTORS[0].bytes), recipientId: REC_B }, /names recipient .* and its bytes carry/],
      ["amount", { ...led.entryForSend("h", VECTORS[0].bytes), amountCredits: "1" }, /names amount .* and its bytes carry/],
    ];
    for (const [what, entry, re] of contradictions) {
      led.clear();
      led.record(entry);
      throws(`a line whose stored ${what} disagrees with its bytes REFUSES rather than being counted`,
        () => led.transfers(), re);
    }

    // THE DECLARED SHAPE IS A STORED CLASSIFICATION TOO. A reservation's bytes stored under the
    // header shape was accepted and silently relabelled before this case existed, which is
    // resolution instead of refusal and is what the rule forbids.
    led.clear();
    led.record({ ...led.entryForSend("h", "0c0d" + ACC_A), shape: "header" });
    throws("a line whose stored SHAPE disagrees with its bytes REFUSES rather than being relabelled",
      () => led.events(), /stored as shape "header" and its bytes are "reservation"/);
    led.clear();
    led.record(led.entryForSend("h", "0c0d" + ACC_A));
    ok("a non-payment line whose shape agrees with its bytes is accepted and not unrecognized",
      led.events().length === 1 && led.unrecognized().length === 0);

    // TWO TRANSFER LINES IDENTICAL IN EVERY FIELD, hash and process included, BOTH COUNT. A
    // review defeated the reader by grouping transfers on hash and process, and neither the two
    // copies here (which used different hashes) nor the run's own control (whose copy carried the
    // parent's process identifier) could see that grouping. This case binds it.
    led.clear();
    const twice = led.entryForSend("same-hash", VECTORS[0].bytes);
    led.record(twice);
    led.record({ ...twice });
    ok("TWO TRANSFER LINES IDENTICAL IN HASH AND PROCESS BOTH COUNT, so the reader cannot group them away",
      led.transfersFor(ACC_A).length === 2);

    // and the refusal is not a blanket one: the same line with its fields agreeing is counted
    led.clear();
    led.record(led.entryForSend("h", VECTORS[0].bytes));
    ok("a line whose stored fields agree with its bytes is counted once",
      led.transfersFor(ACC_A).length === 1);

    led.clear();
    led.record({ kind: "send", hash: "h", pid: 1, at: "now" });   // no bytes at all
    throws("a send carrying no bytes REFUSES rather than being skipped",
      () => led.transfers(), /carrying no bytes/);

    led.clear();
    led.record({ hash: "h", bytes: VECTORS[0].bytes, pid: 1 });   // no kind at all
    throws("a line naming no event kind REFUSES, so a typo cannot become a class every reader ignores",
      () => led.events(), /names kind undefined/);
    led.clear();
    led.record({ kind: "sned", hash: "h", bytes: VECTORS[0].bytes, pid: 1 });
    throws("a line naming an unknown event kind REFUSES",
      () => led.events(), /names kind "sned"/);

    // ---- THE LOG'S ORDER IS THE TIME SOURCE, which is what replaced a reported count ----
    led.clear();
    led.record(led.entryForSend("h1", VECTORS[0].bytes));
    led.record({ kind: "declares-complete", beforeEpoch: 6, completedEpochs: [5], pid: 1 });
    led.record(led.entryForSend("h2", VECTORS[1].bytes));
    led.record({ kind: "final", completedEpochs: [5, 6], nothingLeft: true, pid: 1 });
    const ev = led.events();
    ok("every event carries its own POSITION, assigned by the log rather than by its writer",
      ev.map((e) => e.seq).join(",") === "0,1,2,3");
    ok("what had been paid BEFORE the declaration is read from the order, and it is the first payment alone",
      JSON.stringify(led.paidCountsBefore(1)) === JSON.stringify({ [ACC_A]: 1 }));
    ok("what had been paid before the final event includes both",
      led.paidCountsBefore(3)[ACC_A] === 1 && led.paidCountsBefore(3)[ACC_B] === 1);
    ok("nothing had been paid before the first event", Object.keys(led.paidCountsBefore(0)).length === 0);
    throws("paidCountsBefore refuses a position that is not a non-negative integer",
      () => led.paidCountsBefore(-1), /non-negative position/);

    led.clear();
    fs.appendFileSync(led.path, "{not json\n");
    throws("an unreadable ledger line refuses rather than being skipped",
      () => led.events(), /refusing rather than counting one payment fewer/);

    led.clear();
    ok("clearing the ledger leaves no effects", led.events().length === 0);

    throws("a declared shape that reuses the transfer tag is refused at construction",
      () => L.makeEventLog(path.join(dir, "x.jsonl"),
        { otherShapes: { sneaky: L.TRANSFER_TAG } }), /would make a payment unrecognizable/);

    fs.rmSync(dir, { recursive: true, force: true });
  }

  console.log(`\ne2PaymentLedgerTest: ${passed} passed, ${failed} failed`);
  if (failed) process.exitCode = 1;
};

main();
