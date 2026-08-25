/**
 * Offline test for the journal's semantic layer, revised with the D7
 * checker's findings folded: every constructor computes REAL digests from
 * its own bytes (the checker showed placeholder hashes let the recomputation
 * rule go untested), captures reproduce their write-ahead's content, the
 * driver covers observations, document-write errors, declarations and
 * supersessions, and a composed PHYSICAL case drives real files through the
 * store with a branch copy at a prefix.
 *
 * THE BATTERY'S HONEST WIDTH, stated: prefix closure over in-memory arrays
 * covers the SEMANTIC half of the crash matrix; the composed physical case
 * covers store-level recovery and one branch copy; interruption inside the
 * append transaction is the store test's fault-injection job; and the
 * bounded model SAMPLES the space (seeds recorded below, mulberry32,
 * deterministic replay), never exhausts it.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { validateJournal, openValidatedJournal, K, PROVED_HEADER_ROUTE } = require("./e2Journal.cjs");
const { HEADER_KIND: CAP_HEADER, RECEIPT_KIND: CAP_RECEIPT, SUPERSESSION_KIND,
  preimageDigest } = require("./e2CaptureRecord.cjs");
const { openJournal, appendRecord, journalPath, boundaryPath } = require("./e2JournalStore.cjs");

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
const h32 = (fill) => fill.repeat(64 / fill.length);
const ACC1 = h32("a1"), ACC2 = h32("b2");
const sha = (hexStr) => crypto.createHash("sha256").update(Buffer.from(hexStr, "hex")).digest("hex");

// ---- constructors: REAL digests from their own bytes ----
const lag = (opts = {}) => ({ v: 1, kind: K.DECLARATION, object: "pool", gen: 1, poolId: POOL,
  condition: "lag-measurement", reasoning: "run start", lagCount: opts.lagCount ?? 0,
  undistributedCredits: opts.undist ?? "0",
  ...(opts.first !== undefined ? { configuredStartEpoch: opts.first } : {}) });
const ec = (epoch) => ({ poolId: POOL, epochIndex: epoch, grossCredits: 1000, feeCredits: 10,
  allocationHash: h32("ee"), memberCount: 2, calcVersion: 1 });
const hBytes = (epoch, gen = 1) => "0102" + String(epoch).padStart(4, "0") + String(gen).padStart(2, "0");
const tBytes = (epoch, acc) => "0a0b" + String(epoch).padStart(4, "0") + acc.slice(0, 4);
const rBytes = (epoch, acc, gen = 1) => "0c0d" + String(epoch).padStart(4, "0") + acc.slice(0, 4) + String(gen).padStart(2, "0");
const headerW = (epoch, opts = {}) => {
  const bytes = hBytes(epoch, opts.gen ?? 1);
  return { v: 1, kind: K.WRITE_AHEAD, object: "header", gen: opts.gen ?? 1, poolId: POOL,
    epochIndex: epoch, transitionBytes: bytes, transitionHash: sha(bytes),
    expectedDocumentId: h32("dd"), expectedContents: ec(epoch),
    ...(opts.first ? { configuredStartEpoch: epoch } : {}) };
};
const marker = (object, epoch, acc, bytes, gen = 1) => ({ v: 1, kind: K.SENT_MARKER, object,
  gen, poolId: POOL, epochIndex: epoch, ...(acc ? { accrualId: acc } : {}), transitionHash: sha(bytes) });
const headerCap = (epoch, gen = 1) => ({ v: 1, kind: CAP_HEADER, object: "header", gen,
  poolId: POOL, epochIndex: epoch, transitionBytes: hBytes(epoch, gen),
  transitionHash: sha(hBytes(epoch, gen)), proofMsg: "aa".repeat(20), metadataMsg: "bb".repeat(10),
  contractId: h32("cc"), expectedDocumentId: h32("dd"), expectedContents: ec(epoch),
  inclusionHeight: "1000", heightRoute: "tenderdash-tx", signerIdentity: h32("f0"),
  signerKeyId: 2, sig: "00".repeat(65) });
const transferW = (epoch, acc) => ({ v: 1, kind: K.WRITE_AHEAD, object: "transfer", gen: 1,
  poolId: POOL, epochIndex: epoch, accrualId: acc, transitionBytes: tBytes(epoch, acc),
  transitionHash: sha(tBytes(epoch, acc)) });
const resW = (epoch, acc, gen = 1) => ({ v: 1, kind: K.WRITE_AHEAD, object: "reservation", gen,
  poolId: POOL, epochIndex: epoch, accrualId: acc, transitionBytes: rBytes(epoch, acc, gen),
  transitionHash: sha(rBytes(epoch, acc, gen)), boundTransferHash: sha(tBytes(epoch, acc)) });
const resJ = (epoch, acc, gen = 1) => ({ v: 1, kind: K.RESERVATION_SUCCESS, object: "reservation",
  gen, poolId: POOL, epochIndex: epoch, accrualId: acc, transitionHash: sha(rBytes(epoch, acc, gen)),
  boundTransferHash: sha(tBytes(epoch, acc)), reservationDocumentId: h32("d1") });
const receiptCap = (epoch, acc) => ({ v: 1, kind: CAP_RECEIPT, object: "transfer", gen: 1,
  poolId: POOL, epochIndex: epoch, accrualId: acc, transitionHash: sha(tBytes(epoch, acc)),
  transitionBytes: tBytes(epoch, acc), proofMsg: "cc".repeat(20), metadataMsg: "dd".repeat(10),
  inclusionHeight: "1001", heightRoute: "tenderdash-tx", signerIdentity: h32("f0"),
  signerKeyId: 2, sig: "00".repeat(65) });
const errRec = (object, epoch, acc, cls, gen = 1, extraSubj = {}) => ({ v: 1, kind: K.ERROR, object, gen,
  poolId: POOL, epochIndex: epoch, ...(acc ? { accrualId: acc } : {}), ...extraSubj,
  code: 7, data: "00", message: "structured", errorClass: cls });
const decision = (object, epoch, acc, condition, action, gen = 1, extra = {}) => ({ v: 1,
  kind: K.DECISION, object, gen, poolId: POOL,
  ...(object === "pool" ? {} : { epochIndex: epoch }), ...(acc ? { accrualId: acc } : {}),
  condition, action, d6Status: "open", reasoning: "operator", ...extra });
const surfacing = (object, epoch, acc, condition, gen = 1, extraSubj = {}) => ({ v: 1, kind: K.DECLARATION,
  object, gen, poolId: POOL, ...(object === "pool" ? {} : { epochIndex: epoch }),
  ...(acc ? { accrualId: acc } : {}), ...extraSubj, condition, reasoning: "patience expired" });
const observation = (object, epoch, acc, observationType, gen = 1, extra = {}) => ({ v: 1,
  kind: K.OBSERVATION, object, gen, poolId: POOL, epochIndex: epoch,
  ...(acc ? { accrualId: acc } : {}), observationType, route: "documents-byPoolEpoch", ...extra });

const happyAccrual = (epoch, acc) => [
  transferW(epoch, acc),
  resW(epoch, acc),
  marker("reservation", epoch, acc, rBytes(epoch, acc)),
  resJ(epoch, acc),
  marker("transfer", epoch, acc, tBytes(epoch, acc)),
  receiptCap(epoch, acc),
];
const happyEpoch = (epoch, opts = {}) => [
  headerW(epoch, { first: opts.first }),
  marker("header", epoch, null, hBytes(epoch)),
  headerCap(epoch),
  ...happyAccrual(epoch, ACC1),
];

// ---- the golden path, its read result, and prefix closure ----
{
  const j = [lag({ first: 5 }), ...happyEpoch(5, { first: true }), ...happyAccrual(5, ACC2)];
  const r = validateJournal(POOL, j);
  ok("the golden path validates with real digests", !!r);
  ok("the binding reads back", r.configuredStartEpoch === 5);
  ok("the header derives captured with its expected numbers",
    r.perEpoch[5].header.state === "captured" && r.perEpoch[5].header.memberCount === 2);
  ok("highestEpochIndex covers every epoch-bearing record", r.highestEpochIndex === 5);
  ok("an epoch-scoped declaration bounds highestEpochIndex (perEpoch does not see it)",
    validateJournal(POOL, [lag({ first: 5 }), { v: 1, kind: K.DECLARATION, object: "epoch",
      gen: 1, poolId: POOL, epochIndex: 8, condition: "zero-earning-epoch",
      reasoning: "absent proposer" }]).highestEpochIndex === 8);
  ok("a journal with only pool-scoped records has no highest epoch",
    validateJournal(POOL, [lag({ first: 5 })]).highestEpochIndex === null);
  ok("both accruals derive captured with the receipt flag",
    r.perEpoch[5].accruals[ACC1].receiptCaptured === true
    && r.perEpoch[5].accruals[ACC2].receiptCaptured === true);
  let closed = true;
  for (let n = 0; n <= j.length; n++) {
    try { validateJournal(POOL, j.slice(0, n)); } catch { closed = false; console.error("prefix", n); }
  }
  ok("every prefix of the golden path validates", closed);
}

// ---- the recomputed-hash rules (checker finding 2) ----
throws("a writeAhead whose hash is not SHA-256 of its bytes refuses",
  () => validateJournal(POOL, [lag({ first: 5 }),
    { ...headerW(5, { first: true }), transitionHash: h32("11") }]), /not SHA-256 of transitionBytes/);
{
  // a capture over DIFFERENT bytes refuses on one of two composed routes,
  // both covered: echoing the writeAhead's hash over foreign bytes dies at
  // the capture's own recomputation (record-local self-consistency), and a
  // self-consistent capture of foreign bytes dies at the relational hash
  // equality, which binds the bytes because both sides are recomputed
  const echoed = { ...headerCap(5), transitionBytes: "9999" };
  throws("a capture echoing the writeAhead's hash over foreign bytes refuses",
    () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
      marker("header", 5, null, hBytes(5)), echoed]), /not SHA-256 of transitionBytes/);
  const selfConsistent = { ...headerCap(5), transitionBytes: "9999", transitionHash: sha("9999") };
  throws("a self-consistent capture of foreign bytes refuses at the hash binding",
    () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
      marker("header", 5, null, hBytes(5)), selfConsistent]), /capture hash disagrees/);
}
{
  // ... and the expectedDocumentId check alone, with the bytes honest
  const cap = { ...headerCap(5), expectedDocumentId: h32("d9") };
  throws("a capture whose expectedDocumentId alone differs refuses",
    () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
      marker("header", 5, null, hBytes(5)), cap]), /expectedDocumentId disagrees/);
}
{
  const cap = { ...headerCap(5), expectedContents: { ...ec(5), grossCredits: 999 } };
  throws("a capture whose expectedContents differ byte-for-byte refuses",
    () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
      marker("header", 5, null, hBytes(5)), cap]), /expectedContents disagree/);
}
throws("a header writeAhead whose expectedContents pool/epoch disagree with the subject refuses",
  () => validateJournal(POOL, [lag({ first: 5 }),
    { ...headerW(5, { first: true }), expectedContents: ec(6) }]), /equal the subject tuple/);

// ---- a soundness-review finding ----
throws("a first record that is not the binding measurement refuses",
  () => validateJournal(POOL, [headerW(5, { first: true })]), /a soundness-review finding/);
throws("a binding disagreeing across records refuses",
  () => validateJournal(POOL, [lag({ first: 4 }), ...happyEpoch(5, { first: true })]), /disagrees across records.*a soundness-review finding/s);

// ---- authority and ordering ----
throws("a transfer sentMarker without the holder chain refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), headerCap(5),
    transferW(5, ACC1), marker("transfer", 5, ACC1, tBytes(5, ACC1))]), /holder chain/);
throws("J after an execution-refusal refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), headerCap(5),
    transferW(5, ACC1), resW(5, ACC1), marker("reservation", 5, ACC1, rBytes(5, ACC1)),
    errRec("reservation", 5, ACC1, "execution-refusal"), resJ(5, ACC1)]), /terminal outcome/);
throws("a sentMarker whose hash disagrees with its writeAhead refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
    { ...marker("header", 5, null, hBytes(5)), transitionHash: h32("99") }]), /hash disagrees/);
throws("S without W refuses", () => validateJournal(POOL, [lag({ first: 5 }),
  marker("header", 5, null, hBytes(5))]), /without its writeAhead/);
throws("a second W in one generation refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }), headerW(5)]), /second writeAhead/);

// ---- per-generation evidence and decisions (checker finding 3) ----
throws("a nonterminal unique-index error cannot surface header-refused",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), errRec("header", 5, null, "unique-index"),
    surfacing("header", 5, null, "header-refused")]), /exact establishing evidence/);
{
  const j = [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), errRec("header", 5, null, "execution-refusal"),
    surfacing("header", 5, null, "header-refused"),
    decision("header", 5, null, "header-refused", "rebuild-corrected"),
    headerW(5, { gen: 2 }), marker("header", 5, null, hBytes(5, 2), 2), headerCap(5, 2)];
  ok("the consumed rebuild path with real digests validates", !!validateJournal(POOL, j));
  throws("a decision on a non-current generation refuses",
    () => validateJournal(POOL, [...j,
      decision("header", 5, null, "header-refused", "rebuild-corrected", 1)]), /current generation/);
  throws("the consumed rebuild cannot open a third generation",
    () => validateJournal(POOL, [...j, headerW(5, { gen: 3 })]), /no unconsumed/);
}
{
  const pre = [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), headerCap(5),
    transferW(5, ACC1), resW(5, ACC1), marker("reservation", 5, ACC1, rBytes(5, ACC1)),
    resJ(5, ACC1), marker("transfer", 5, ACC1, tBytes(5, ACC1)),
    surfacing("transfer", 5, ACC1, "transfer-unresolved"),
    decision("transfer", 5, ACC1, "transfer-unresolved", "rebroadcast-identical")];
  ok("an adjacent authorized rebroadcast validates",
    !!validateJournal(POOL, [...pre, marker("transfer", 5, ACC1, tBytes(5, ACC1)), receiptCap(5, ACC1)]));
  throws("a rebroadcast whose decision is not adjacent refuses",
    () => validateJournal(POOL, [...pre,
      observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: sha(tBytes(5, ACC1)) }),
      marker("transfer", 5, ACC1, tBytes(5, ACC1))]), /immediately follow/);
}

// ---- the observation loop as a closed machine (checker finding 4) ----
throws("receipt-observed without a watch refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), transferW(5, ACC1),
    observation("transfer", 5, ACC1, "receipt-observed", 1, { observedDocumentId: h32("0d") })]),
  /without a prior watch-open/);
throws("a second watch-open refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), transferW(5, ACC1),
    observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: sha(tBytes(5, ACC1)) }),
    observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: sha(tBytes(5, ACC1)) })]),
  /second watch-open/);
throws("a second receipt-observed refuses (the loop closed)",
  () => validateJournal(POOL, [lag({ first: 5 }), transferW(5, ACC1),
    observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: sha(tBytes(5, ACC1)) }),
    observation("transfer", 5, ACC1, "receipt-observed", 1, { observedDocumentId: h32("0d") }),
    observation("transfer", 5, ACC1, "receipt-observed", 1, { observedDocumentId: h32("0d") })]),
  /loop is closed/);
throws("observation-unresolved without the watch refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), transferW(5, ACC1),
    surfacing("transfer", 5, ACC1, "observation-unresolved")]), /exact establishing evidence/);
throws("a watch-open on a generation with no writeAhead refuses (evidence without an attempt)",
  () => validateJournal(POOL, [lag({ first: 5 }),
    observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: sha(tBytes(5, ACC1)) })]),
  /generation with no writeAhead/);
throws("a watch-open whose target hash differs from the writeAhead refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), transferW(5, ACC1),
    observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: h32("77") })]),
  /targetTransitionHash disagrees/);
throws("a watch-open after the terminal receipt capture refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), headerCap(5), ...happyAccrual(5, ACC1),
    observation("transfer", 5, ACC1, "watch-open", 1, { targetTransitionHash: sha(tBytes(5, ACC1)) })]),
  /watch-open after the terminal outcome/);
{
  // the foreign-claim evidence must carry the OBSERVED differing hash
  const base = [lag({ first: 5 }), transferW(5, ACC1), resW(5, ACC1)];
  ok("a foreign-claim observation with both hashes validates",
    !!validateJournal(POOL, [...base,
      observation("reservation", 5, ACC1, "foreign-claim", 1,
        { targetTransitionHash: sha(rBytes(5, ACC1)), observedBoundTransferHash: h32("99") })]));
  throws("an equal observed binding cannot establish a foreign claim (the wait-only path)",
    () => validateJournal(POOL, [...base,
      observation("reservation", 5, ACC1, "foreign-claim", 1,
        { targetTransitionHash: sha(rBytes(5, ACC1)),
          observedBoundTransferHash: sha(tBytes(5, ACC1)) })]), /must differ/);
  throws("a foreign-claim observation without the observed hash refuses",
    () => validateJournal(POOL, [...base,
      observation("reservation", 5, ACC1, "foreign-claim", 1,
        { targetTransitionHash: sha(rBytes(5, ACC1)) })]), /missing member observedBoundTransferHash/);
}
throws("an observation type on the wrong object refuses",
  () => validateJournal(POOL, [lag({ first: 5 }),
    observation("header", 5, null, "watch-open", 1, { targetTransitionHash: h32("22") })]),
  /binds object transfer/);
{
  const fullFields = { poolId: POOL, ...ec(5) }; // the seven-field equality's subject
  const base = [lag({ first: 5 }), headerW(5, { first: true }), marker("header", 5, null, hBytes(5)),
    observation("header", 5, null, "foreign-document", 1,
      { observedDocumentId: h32("dd"), observedFields: fullFields })];
  throws("header-capture-incomplete without the proved-route observation refuses",
    () => validateJournal(POOL, [...base, surfacing("header", 5, null, "header-capture-incomplete")]),
    /exact establishing evidence/);
  const proved = (over = {}) => ({ ...observation("header", 5, null, "foreign-document", 1,
    { observedDocumentId: over.docId || h32("dd"),
      observedFields: over.fields || fullFields }), route: PROVED_HEADER_ROUTE });
  ok("the proved EQUAL observation plus surfacing establishes header-capture-incomplete",
    !!validateJournal(POOL, [...base, proved(),
      surfacing("header", 5, null, "header-capture-incomplete"),
      decision("header", 5, null, "header-capture-incomplete", "continue-degraded")]));
  // a proved MISMATCH is header-foreign evidence, never the degraded
  // continuation: a different document identifier or a differing field
  // cannot unlock header-capture-incomplete (the distribution fold
  // re-check's F1)
  throws("a proved observation of a DIFFERENT document cannot establish the degraded continuation",
    () => validateJournal(POOL, [...base, proved({ docId: h32("99") }),
      surfacing("header", 5, null, "header-capture-incomplete")]),
    /exact establishing evidence/);
  throws("a proved observation with a differing field cannot establish the degraded continuation",
    () => validateJournal(POOL, [...base, proved({ fields: { ...fullFields, grossCredits: 999 } }),
      surfacing("header", 5, null, "header-capture-incomplete")]),
    /exact establishing evidence/);
  ok("the same mismatched proved observation still establishes header-foreign",
    !!validateJournal(POOL, [...base, proved({ docId: h32("99") }),
      surfacing("header", 5, null, "header-foreign"),
      decision("header", 5, null, "header-foreign", "stop", 1, { targetDocumentId: h32("99") })]));
}

// ---- document-write and generation-1 rules (checker finding 5) ----
throws("an accrual error at generation 2 refuses",
  () => validateJournal(POOL, [lag({ first: 5 }),
    errRec("accrual", 5, ACC1, "execution-refusal", 2)]), /generation 1 only/);
throws("a transfer unique-index error class refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), headerCap(5),
    ...happyAccrual(5, ACC1).slice(0, 5),
    errRec("transfer", 5, ACC1, "unique-index")]), /not applicable to transfers/);
{
  const j = [lag({ first: 5 }),
    errRec("receipt", 5, ACC1, "unique-index"),
    surfacing("receipt", 5, ACC1, "record-write-unresolved"),
    decision("receipt", 5, ACC1, "record-write-unresolved", "keep-waiting")];
  ok("the document-write unresolved path (error, surfacing, decision) validates",
    !!validateJournal(POOL, j));
}
{
  // the patience-expiry surfacing may be the subject's FIRST record: the
  // document-write loop journals nothing on an ambiguous outcome, so this
  // condition requires no prior evidence (the trigger table's "error or
  // first record" row), and a SECOND expiry after keep-waiting also passes
  const j = [lag({ first: 5 }),
    surfacing("receipt", 5, ACC1, "record-write-unresolved"),
    decision("receipt", 5, ACC1, "record-write-unresolved", "keep-waiting"),
    surfacing("receipt", 5, ACC1, "record-write-unresolved"),
    decision("receipt", 5, ACC1, "record-write-unresolved", "stop")];
  ok("a patience-expiry surfacing as the subject's first record validates, twice",
    !!validateJournal(POOL, j));
}
{
  const j = [lag({ first: 5 }),
    errRec("part", 5, ACC1, "execution-refusal", 1, { partIndex: 3 }),
    surfacing("part", 5, ACC1, "record-write-refused", 1, { partIndex: 3 }),
    { ...decision("part", 5, ACC1, "record-write-refused", "stop"), partIndex: 3 }];
  ok("a part refusal with stop validates and derives its state",
    validateJournal(POOL, j).perEpoch[5].documentWriteSubjects[`part:${ACC1}:3`].state === "refused");
}

// ---- supersession chain rules validated in the journal (checker finding 7) ----
{
  const base = [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), headerCap(5)];
  const cap = base[3];
  const sup = (seq, over = {}) => ({ v: 1, kind: SUPERSESSION_KIND, object: "header", gen: 1,
    poolId: POOL, epochIndex: 5, supersededKind: CAP_HEADER,
    transitionHash: cap.transitionHash, preimageHash: preimageDigest(cap), seq,
    signerIdentity: h32("f0"), signerKeyId: 5, sig: "11".repeat(65), ...over });
  ok("a contiguous supersession chain validates", !!validateJournal(POOL, [...base, sup(1), sup(2)]));
  throws("a supersession before its capture refuses",
    () => validateJournal(POOL, [lag({ first: 5 }), headerW(5, { first: true }), sup(1)]),
    /precedes the capture/);
  throws("a seq starting at 4 refuses", () => validateJournal(POOL, [...base, sup(4)]), /contiguous from 1/);
  throws("a foreign preimageHash refuses",
    () => validateJournal(POOL, [...base, sup(1, { preimageHash: h32("88") })]), /preimageHash disagrees/);
}

// ---- stop terminality ----
{
  const stopped = [lag({ first: 5 }), headerW(5, { first: true }),
    marker("header", 5, null, hBytes(5)), errRec("header", 5, null, "execution-refusal"),
    surfacing("header", 5, null, "header-refused"),
    decision("header", 5, null, "header-refused", "stop")];
  ok("a consumed stop validates", !!validateJournal(POOL, stopped));
  throws("a record after a consumed stop refuses",
    () => validateJournal(POOL, [...stopped, headerW(5, { gen: 2 })]), /consumed stop/);
  throws("a later decision after a consumed stop refuses",
    () => validateJournal(POOL, [...stopped,
      decision("header", 5, null, "header-refused", "rebuild-corrected")]), /consumed stop/);
}
throws("distribution-lagging as a journal record refuses",
  () => validateJournal(POOL, [lag({ first: 5 }),
    { ...lag(), condition: "distribution-lagging" }]), /derived, never a journal record/);
throws("a foreign pool's record refuses",
  () => validateJournal(POOL, [lag({ first: 5 }), { ...headerW(5, { first: true }), poolId: h32("cd") }]), /foreign pool/);

// ---- the COMPOSED PHYSICAL case: real files, a branch copy at a prefix,
// and the composed open-and-validate operation (checker findings 8 and 10) ----
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-e2jr-"));
  const j = [lag({ first: 5 }), ...happyEpoch(5, { first: true })];
  let off = openJournal(POOL, dir).committedOffset;
  const branchAt = 4;
  let branchDir = null;
  j.forEach((rec, idx) => {
    off = appendRecord(POOL, off, rec, dir);
    if (idx === branchAt - 1) {
      branchDir = fs.mkdtempSync(path.join(os.tmpdir(), "tegara-e2jb-"));
      fs.copyFileSync(journalPath(POOL, dir), journalPath(POOL, branchDir));
      fs.copyFileSync(boundaryPath(POOL, dir), boundaryPath(POOL, branchDir));
    }
  });
  const main = openValidatedJournal(POOL, dir);
  ok("the composed open-and-validate returns the derived state off real files",
    main.perEpoch[5].header.state === "captured" && main.committedOffset === off);
  const branch = openValidatedJournal(POOL, branchDir);
  ok("a branch copy at a prefix is a valid journal of the same lineage",
    branch.records.length === branchAt && branch.configuredStartEpoch === 5);
  ok("the branch can append its own continuation",
    (() => { appendRecord(POOL, branch.committedOffset, transferW(5, ACC2), branchDir);
      return openValidatedJournal(POOL, branchDir).records.length === branchAt + 1; })());
}

// ---- THE SEEDED FUZZ over the WIDENED model: headers (clean, refused with
// rebuild or stop, unique-index annotations, supersessions), reservations
// (success or refusal), transfers (capture, rebroadcast, or observer watch
// loops), document-write errors, epoch declarations; full validation +
// prefix closure + the authority mutation on every seed ----
const mulberry32 = (seed) => () => {
  seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const FUZZ_SEEDS = [11, 47, 1009, 20260821, 424242];
const buildRandomJournal = (rnd) => {
  const j = [lag({ first: 5 })];
  for (const epoch of [5, 6]) {
    if (epoch === 6 && rnd() < 0.3) break;
    const first = epoch === 5;
    j.push(headerW(epoch, { first }));
    j.push(marker("header", epoch, null, hBytes(epoch)));
    if (rnd() < 0.25) {
      j.push(errRec("header", epoch, null, "execution-refusal"));
      j.push(surfacing("header", epoch, null, "header-refused"));
      if (rnd() < 0.5) {
        j.push(decision("header", epoch, null, "header-refused", "rebuild-corrected"));
        j.push(headerW(epoch, { gen: 2 }));
        j.push(marker("header", epoch, null, hBytes(epoch, 2), 2));
        j.push(headerCap(epoch, 2));
      } else {
        j.push(decision("header", epoch, null, "header-refused", "stop"));
        continue;
      }
    } else {
      if (rnd() < 0.3) j.push(errRec("header", epoch, null, "unique-index"));
      j.push(headerCap(epoch));
      if (rnd() < 0.3) {
        const cap = j[j.length - 1];
        j.push({ v: 1, kind: SUPERSESSION_KIND, object: "header", gen: cap.gen, poolId: POOL,
          epochIndex: epoch, supersededKind: CAP_HEADER, transitionHash: cap.transitionHash,
          preimageHash: preimageDigest(cap), seq: 1, signerIdentity: h32("f0"),
          signerKeyId: 5, sig: "11".repeat(65) });
      }
    }
    for (const acc of rnd() < 0.5 ? [ACC1] : [ACC1, ACC2]) {
      j.push(transferW(epoch, acc));
      if (rnd() < 0.15) {
        j.push(observation("transfer", epoch, acc, "watch-open", 1,
          { targetTransitionHash: sha(tBytes(epoch, acc)) }));
        if (rnd() < 0.5) j.push(observation("transfer", epoch, acc, "receipt-observed", 1,
          { observedDocumentId: h32("0d") }));
        continue;
      }
      j.push(resW(epoch, acc));
      j.push(marker("reservation", epoch, acc, rBytes(epoch, acc)));
      if (rnd() < 0.2) {
        j.push(errRec("reservation", epoch, acc, "execution-refusal"));
        j.push(surfacing("reservation", epoch, acc, "reservation-refused"));
        j.push(decision("reservation", epoch, acc, "reservation-refused", "stop"));
        continue;
      }
      j.push(resJ(epoch, acc));
      j.push(marker("transfer", epoch, acc, tBytes(epoch, acc)));
      if (rnd() < 0.25) {
        j.push(surfacing("transfer", epoch, acc, "transfer-unresolved"));
        j.push(decision("transfer", epoch, acc, "transfer-unresolved", "rebroadcast-identical"));
        j.push(marker("transfer", epoch, acc, tBytes(epoch, acc)));
      }
      j.push(receiptCap(epoch, acc));
      if (rnd() < 0.2) j.push(errRec("receipt", epoch, acc, "unique-index"));
    }
    if (rnd() < 0.4) j.push(lag({ lagCount: 1, undist: "500" }));
    if (rnd() < 0.3) j.push({ v: 1, kind: K.DECLARATION, object: "epoch", gen: 1, poolId: POOL,
      epochIndex: epoch, condition: "zero-earning-epoch", reasoning: "absent proposer" });
  }
  return j;
};
for (const seed of FUZZ_SEEDS) {
  const rnd = mulberry32(seed);
  const j = buildRandomJournal(rnd);
  let full = true, prefixes = true, authority = true;
  try { validateJournal(POOL, j); } catch (e) { full = false; console.error("seed", seed, e.message); }
  for (let n = 0; n <= j.length && prefixes; n++) {
    try { validateJournal(POOL, j.slice(0, n)); } catch (e) { prefixes = false; console.error("seed", seed, "prefix", n, e.message); }
  }
  const noJ = j.filter((r) => r.kind !== K.RESERVATION_SUCCESS);
  if (noJ.some((r) => r.kind === K.SENT_MARKER && r.object === "transfer")) {
    try { validateJournal(POOL, noJ); authority = false; } catch { /* refused */ }
  }
  ok(`seed ${seed}: full validation, prefix closure, authority mutation refuses`,
    full && prefixes && authority);
}

console.log(`e2JournalTest: ${passed} passed, ${failed} failed`);
if (failed) process.exitCode = 1;
