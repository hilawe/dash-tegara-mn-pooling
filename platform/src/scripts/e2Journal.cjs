/**
 * The E2 journal's SEMANTIC layer (duty D7): the closed record schemas, the
 * per-object transition grammar, decision consumption, the condition-trigger
 * evidence table, the a soundness-review finding configured-start binding, and the validator's
 * CLOSED READ RESULT. Revised wholesale after the D7 checker's ten findings
 * (record the private review records, in the fold commit): hashes
 * are RECOMPUTED never trusted, evidence and decisions are per-generation
 * with exact classes, the observation loop is a closed machine, non-broadcast
 * subjects are generation-1 only, captures must reproduce their write-ahead's
 * bytes, supersessions are chain-validated here, and the read result carries
 * the admission inventory's inputs at their honest journal-local width.
 *
 * WHAT THE VALIDATOR ESTABLISHES: a journal is well formed under the frozen
 * contract as a WHOLE (any failure refuses everything; there is no partial
 * acceptance). Every transitionHash is SHA-256 of its own transitionBytes,
 * recomputed here. A transfer sent-marker (broadcast authority) requires the
 * reservation's valid W-S-J chain in its CURRENT generation, bound to the
 * transfer write-ahead's RECOMPUTED hash. A capture reproduces its
 * write-ahead's transition bytes (headers additionally the expected document
 * identifier and the canonical expected contents, whose poolId and epoch
 * equal the subject's). Decisions act on their subject's current generation,
 * on evidence of the EXACT class their condition's trigger row names, in
 * that generation; a repeated transfer marker consumes its authorizing
 * rebroadcast decision as the subject's IMMEDIATELY PRECEDING record. Stop
 * is terminal and unsupersedable. Pool, epoch, accrual, part and receipt
 * subjects are generation 1 only, and a transfer unique-index error class is
 * refused as not applicable. a soundness-review finding binding holds three ways.
 *
 * WHAT IT DOES NOT ESTABLISH: proof verification (the receipt verifier),
 * key authorization (the pinned identity routes), or the ledger's state. A
 * successful DOCUMENT WRITE produces no journal record by contract, so the
 * read result's per-epoch view is the JOURNAL-LOCAL width: expected numbers
 * from the header write-ahead, per-accrual broadcast states, capture flags,
 * and error/stop states for document-write subjects. Written accruals and
 * parts are NOT enumerable from the journal, and the admission consumer's
 * conservative formula (memberCount-based) is what that width supports.
 *
 * STRICTER-THAN-FROZEN predicates, deliberate and named for the fold-back
 * review: transitionBytes, observation routes and decision reasoning must be
 * NONEMPTY (an empty value satisfies "hex"/"string" but can carry no
 * evidence), and counts are non-negative. The observation route for the
 * PROVED header observation is the literal "documents-byPoolEpoch-proved",
 * an implementation pin pending the route registry's fold-back.
 */
const crypto = require("crypto");
const { canonicalString } = require("./canonicalJson.cjs");
const {
  HEADER_KIND: CAP_HEADER, RECEIPT_KIND: CAP_RECEIPT, SUPERSESSION_KIND,
  validateRecordShape: validateCaptureShape, validateExpectedContents, preimageDigest,
} = require("./e2CaptureRecord.cjs");
const { openJournal } = require("./e2JournalStore.cjs");

const K = {
  WRITE_AHEAD: "tegara.e2.journal.writeAhead.v1",
  SENT_MARKER: "tegara.e2.journal.sentMarker.v1",
  RESERVATION_SUCCESS: "tegara.e2.journal.reservationSuccess.v1",
  ERROR: "tegara.e2.journal.error.v1",
  DECISION: "tegara.e2.journal.decision.v1",
  OBSERVATION: "tegara.e2.journal.observation.v1",
  DECLARATION: "tegara.e2.journal.declaration.v1",
};
const PROVED_HEADER_ROUTE = "documents-byPoolEpoch-proved";

const HEX_RE = /^([0-9a-f]{2})*$/;
const hexLen = (s, bytes) => typeof s === "string" && HEX_RE.test(s) && s.length === bytes * 2;
const decRe = /^(0|[1-9][0-9]*)$/;
const u32 = (n) => Number.isSafeInteger(n) && n >= 0 && n <= 4294967295;
const sha256hex = (hexStr) => crypto.createHash("sha256").update(Buffer.from(hexStr, "hex")).digest("hex");

const refuse = (why, i) => {
  throw new Error(`e2Journal: ${why}${i === undefined ? "" : ` (record ${i})`}; refusing the journal`);
};

const SUBJECT_MEMBERS = {
  pool: ["poolId"],
  epoch: ["poolId", "epochIndex"],
  header: ["poolId", "epochIndex"],
  reservation: ["poolId", "epochIndex", "accrualId"],
  transfer: ["poolId", "epochIndex", "accrualId"],
  accrual: ["poolId", "epochIndex", "accrualId"],
  receipt: ["poolId", "epochIndex", "accrualId"],
  part: ["poolId", "epochIndex", "accrualId", "partIndex"],
};
const BROADCAST_OBJECTS = ["header", "reservation", "transfer"];
const subjectKey = (r) => [r.object, r.poolId, r.epochIndex ?? "", r.accrualId ?? "", r.partIndex ?? ""].join("|");

const ACTIONS = {
  "header-refused": ["stop", "rebuild-corrected"],
  "header-unresolved": ["keep-waiting", "stop"],
  "header-foreign": ["stop"],
  "header-capture-incomplete": ["continue-degraded", "keep-waiting"],
  "reservation-refused": ["stop", "rebuild-reservation"],
  "reservation-foreign": ["stop", "observe-foreign"],
  "reservation-unresolved": ["keep-waiting", "stop"],
  "transfer-refused": ["stop"],
  "transfer-unresolved": ["keep-waiting", "rebroadcast-identical"],
  "observation-unresolved": ["keep-waiting", "stop"],
  "record-write-refused": ["stop"],
  "record-write-unresolved": ["keep-waiting", "stop"],
};
const DECISION_CONDITIONS = Object.keys(ACTIONS);
const DECLARATION_CONDITIONS = ["receipt-unencodable", "transfer-unencodable", "encoding-refused",
  "zero-entitlement", "zero-earning-epoch", "lag-measurement"];
const CONDITION_OBJECT = {
  "header-refused": "header", "header-unresolved": "header", "header-foreign": "header",
  "header-capture-incomplete": "header",
  "reservation-refused": "reservation", "reservation-foreign": "reservation",
  "reservation-unresolved": "reservation",
  "transfer-refused": "transfer", "transfer-unresolved": "transfer",
  "observation-unresolved": "transfer",
  "record-write-refused": null, "record-write-unresolved": null,
  "receipt-unencodable": "accrual", "transfer-unencodable": "accrual",
  "encoding-refused": "epoch", "zero-entitlement": "epoch", "zero-earning-epoch": "epoch",
  "lag-measurement": "pool",
};
// observation types bound to their subjects (checker finding 4)
const OBSERVATION_OBJECT = {
  "foreign-document": "header",
  "foreign-claim": "reservation",
  "watch-open": "transfer",
  "receipt-observed": "transfer",
};

const requireMembers = (r, members, i) => {
  for (const m of members) if (!(m in r)) refuse(`missing member ${m} for ${r.kind}`, i);
  for (const k of Object.keys(r)) {
    if (!members.includes(k)) refuse(`extra member ${k} for ${r.kind} (the member list is closed)`, i);
  }
};

const validateJournalRecord = (r, i, poolId, isFirstRecord, seenFirstHeaderWA) => {
  if (!r || typeof r !== "object" || Array.isArray(r)) refuse("record is not an object", i);
  if (r.kind === CAP_HEADER || r.kind === CAP_RECEIPT || r.kind === SUPERSESSION_KIND) {
    validateCaptureShape(r);
    if (r.poolId !== poolId) refuse("capture names a foreign pool", i);
    return;
  }
  if (r.v !== 1) refuse("v must be the integer 1", i);
  const subj = SUBJECT_MEMBERS[r.object];
  if (!subj) refuse(`unknown object ${JSON.stringify(r.object)}`, i);
  if (r.poolId !== poolId) refuse("record names a foreign pool", i);
  if (!Number.isSafeInteger(r.gen) || r.gen < 1) refuse("gen must be an integer at least 1", i);
  // generation 1 ONLY outside the broadcast objects (checker finding 5)
  if (!BROADCAST_OBJECTS.includes(r.object) && r.gen !== 1) {
    refuse(`object ${r.object} has generation 1 only in conformance`, i);
  }
  if (subj.includes("epochIndex") && !u32(r.epochIndex)) refuse("epochIndex must be u32", i);
  if (subj.includes("accrualId") && !hexLen(r.accrualId, 32)) refuse("accrualId must be 32 bytes hex", i);
  if (subj.includes("partIndex") && !(Number.isSafeInteger(r.partIndex) && r.partIndex >= 1 && r.partIndex <= 7)) {
    refuse("partIndex must be 1..7", i);
  }
  const base = ["v", "kind", "object", "gen", ...subj];
  switch (r.kind) {
    case K.WRITE_AHEAD: {
      const extra = [];
      if (r.object === "header") {
        extra.push("expectedDocumentId", "expectedContents");
        if ("configuredStartEpoch" in r) extra.push("configuredStartEpoch");
      } else if (r.object === "reservation") extra.push("boundTransferHash");
      else if (r.object !== "transfer") refuse(`writeAhead exists only for broadcast objects, not ${r.object}`, i);
      requireMembers(r, [...base, "transitionBytes", "transitionHash", ...extra], i);
      if (!(typeof r.transitionBytes === "string" && HEX_RE.test(r.transitionBytes) && r.transitionBytes.length > 0)) {
        refuse("transitionBytes must be nonempty lowercase hex", i);
      }
      if (!hexLen(r.transitionHash, 32)) refuse("transitionHash must be 32 bytes hex", i);
      // THE HASH IS RECOMPUTED, NEVER TRUSTED (checker finding 2, critical)
      if (r.transitionHash !== sha256hex(r.transitionBytes)) {
        refuse("transitionHash is not SHA-256 of transitionBytes", i);
      }
      if (r.object === "header") {
        if (!hexLen(r.expectedDocumentId, 32)) refuse("expectedDocumentId must be 32 bytes hex", i);
        const e = validateExpectedContents(r.expectedContents); if (e) refuse(e, i);
        if (r.expectedContents.poolId !== r.poolId || r.expectedContents.epochIndex !== r.epochIndex) {
          refuse("expectedContents' pool and epoch must equal the subject tuple", i);
        }
        if ("configuredStartEpoch" in r) {
          if (seenFirstHeaderWA) refuse("configuredStartEpoch appears on a non-first header writeAhead", i);
          if (r.configuredStartEpoch !== r.epochIndex) {
            refuse("the first header writeAhead's configuredStartEpoch must equal its own epochIndex", i);
          }
        } else if (!seenFirstHeaderWA) {
          refuse("the pool's first header writeAhead must carry configuredStartEpoch", i);
        }
      }
      if (r.object === "reservation" && !hexLen(r.boundTransferHash, 32)) {
        refuse("boundTransferHash must be 32 bytes hex", i);
      }
      break;
    }
    case K.SENT_MARKER:
      if (!BROADCAST_OBJECTS.includes(r.object)) refuse(`sentMarker on ${r.object}`, i);
      requireMembers(r, [...base, "transitionHash"], i);
      if (!hexLen(r.transitionHash, 32)) refuse("sentMarker transitionHash must be 32 bytes hex", i);
      break;
    case K.RESERVATION_SUCCESS:
      if (r.object !== "reservation") refuse("reservationSuccess must have object reservation", i);
      requireMembers(r, [...base, "transitionHash", "boundTransferHash", "reservationDocumentId"], i);
      for (const [m, b] of [["transitionHash", 32], ["boundTransferHash", 32], ["reservationDocumentId", 32]]) {
        if (!hexLen(r[m], b)) refuse(`${m} must be ${b} bytes hex`, i);
      }
      break;
    case K.ERROR:
      requireMembers(r, [...base, "code", "data", "message", "errorClass"], i);
      if (!Number.isSafeInteger(r.code)) refuse("error code must be an integer", i);
      if (!(typeof r.data === "string" && HEX_RE.test(r.data))) refuse("error data must be lowercase hex", i);
      if (typeof r.message !== "string") refuse("error message must be a string", i);
      if (!["execution-refusal", "unique-index"].includes(r.errorClass)) refuse("errorClass outside the closed pair", i);
      // a credit transfer is not a document create; no unique index applies
      // (the outcome table; checker finding 5)
      if (r.object === "transfer" && r.errorClass === "unique-index") {
        refuse("a unique-index error class is not applicable to transfers", i);
      }
      break;
    case K.DECISION: {
      if (!DECISION_CONDITIONS.includes(r.condition)) refuse(`decision condition ${r.condition} outside the partition`, i);
      const extra = r.condition === "header-foreign" ? ["targetDocumentId"] : [];
      requireMembers(r, [...base, "condition", "action", "d6Status", "reasoning", ...extra], i);
      if (!ACTIONS[r.condition].includes(r.action)) refuse(`action ${r.action} outside the closed set for ${r.condition}`, i);
      if (!["open", "closed"].includes(r.d6Status)) refuse("d6Status outside the closed pair", i);
      if (typeof r.reasoning !== "string" || r.reasoning.length === 0) refuse("reasoning must be nonempty", i);
      if (extra.length && !hexLen(r.targetDocumentId, 32)) refuse("targetDocumentId must be 32 bytes hex", i);
      const wantObj = CONDITION_OBJECT[r.condition];
      if (wantObj !== null && r.object !== wantObj) refuse(`condition ${r.condition} binds object ${wantObj}`, i);
      if (wantObj === null && !["accrual", "part", "receipt"].includes(r.object)) {
        refuse(`condition ${r.condition} binds a document-write object`, i);
      }
      break;
    }
    case K.OBSERVATION: {
      const byType = {
        "foreign-document": ["observedDocumentId", "observedFields"],
        // observedBoundTransferHash added as an interface correction under
        // the D7 freeze (the distribution second half's checker, F4): the
        // foreign-claim evidence must record WHICH differing on-ledger
        // hash was observed, or the record proves only that a fetch ran
        "foreign-claim": ["targetTransitionHash", "observedBoundTransferHash"],
        "watch-open": ["targetTransitionHash"],
        "receipt-observed": ["observedDocumentId"],
      };
      const extra = byType[r.observationType];
      if (!extra) refuse(`observationType ${r.observationType} outside the closed set`, i);
      if (r.object !== OBSERVATION_OBJECT[r.observationType]) {
        refuse(`observation type ${r.observationType} binds object ${OBSERVATION_OBJECT[r.observationType]}`, i);
      }
      requireMembers(r, [...base, "observationType", "route", ...extra], i);
      if (typeof r.route !== "string" || r.route.length === 0) refuse("route must be nonempty", i);
      if ("observedDocumentId" in r && !hexLen(r.observedDocumentId, 32)) refuse("observedDocumentId must be 32 bytes hex", i);
      if ("targetTransitionHash" in r && !hexLen(r.targetTransitionHash, 32)) refuse("targetTransitionHash must be 32 bytes hex", i);
      if ("observedBoundTransferHash" in r && !hexLen(r.observedBoundTransferHash, 32)) {
        refuse("observedBoundTransferHash must be 32 bytes hex", i);
      }
      // a foreign-claim's observed binding must DIFFER from this branch's
      // own (an equal hash is an identical claim, the wait-only path, and
      // must never establish the foreign condition; the fold re-check's
      // F1). The comparison runs in the machine branch below where the
      // generation's write-ahead is at hand.
      if ("observedFields" in r && (!r.observedFields || typeof r.observedFields !== "object" || Array.isArray(r.observedFields))) {
        refuse("observedFields must be a non-array object", i);
      }
      break;
    }
    case K.DECLARATION: {
      const cond = r.condition;
      if (cond === "distribution-lagging") refuse("distribution-lagging is derived, never a journal record", i);
      let extra = ["reasoning"];
      if (DECLARATION_CONDITIONS.includes(cond)) {
        if (cond === "lag-measurement") {
          extra = ["reasoning", "lagCount", "undistributedCredits"];
          if (isFirstRecord) extra.push("configuredStartEpoch");
        } else if (cond === "encoding-refused") extra = ["reasoning", "field", "value"];
        else if (cond === "receipt-unencodable") extra = ["reasoning", "proofLength"];
        else if (cond === "transfer-unencodable") extra = ["reasoning", "field", "observedLength", "bound"];
        const wantObj = CONDITION_OBJECT[cond];
        if (r.object !== wantObj) refuse(`declaration condition ${cond} binds object ${wantObj}`, i);
      } else if (DECISION_CONDITIONS.includes(cond)) {
        // a SURFACING declaration binds the same object its condition does
        const wantObj = CONDITION_OBJECT[cond];
        if (wantObj !== null && r.object !== wantObj) refuse(`surfacing condition ${cond} binds object ${wantObj}`, i);
        if (wantObj === null && !["accrual", "part", "receipt"].includes(r.object)) {
          refuse(`surfacing condition ${cond} binds a document-write object`, i);
        }
      } else refuse(`declaration condition ${cond} outside both partitions`, i);
      requireMembers(r, [...base, "condition", ...extra], i);
      if (typeof r.reasoning !== "string" || r.reasoning.length === 0) refuse("reasoning must be nonempty", i);
      if (cond === "lag-measurement") {
        if (!Number.isSafeInteger(r.lagCount) || r.lagCount < 0) refuse("lagCount must be a non-negative integer", i);
        if (typeof r.undistributedCredits !== "string" || !decRe.test(r.undistributedCredits)) {
          refuse("undistributedCredits must be a canonical decimal string", i);
        }
        if ("configuredStartEpoch" in r) {
          if (!isFirstRecord) refuse("configuredStartEpoch appears on a non-first record", i);
          if (!u32(r.configuredStartEpoch)) refuse("configuredStartEpoch must be u32", i);
        }
      }
      if (cond === "encoding-refused") {
        if (!["grossCredits", "feeCredits", "amountCredits"].includes(r.field)) refuse("encoding-refused field outside its enum", i);
        if (typeof r.value !== "string" || !decRe.test(r.value)) refuse("encoding-refused value must be canonical decimal", i);
      }
      if (cond === "receipt-unencodable" && !(Number.isSafeInteger(r.proofLength) && r.proofLength >= 0)) {
        refuse("proofLength must be a non-negative integer", i);
      }
      if (cond === "transfer-unencodable") {
        if (r.field !== "transitionBytes") refuse('transfer-unencodable field must be "transitionBytes"', i);
        if (!Number.isSafeInteger(r.observedLength) || !Number.isSafeInteger(r.bound)) {
          refuse("transfer-unencodable lengths must be integers", i);
        }
      }
      break;
    }
    default:
      refuse(`unknown kind ${JSON.stringify(r.kind)}`, i);
  }
};

const STATE_BEARING = new Set([K.WRITE_AHEAD, K.SENT_MARKER, K.RESERVATION_SUCCESS,
  K.ERROR, K.OBSERVATION, CAP_HEADER, CAP_RECEIPT]);

const validateJournal = (poolId, records) => {
  if (!Array.isArray(records)) refuse("records is not an array");
  let binding = null;
  if (records.length > 0) {
    const r0 = records[0];
    if (!(r0 && r0.kind === K.DECLARATION && r0.condition === "lag-measurement"
      && "configuredStartEpoch" in r0)) {
      refuse("the pool's first record must be the run-start lag-measurement carrying configuredStartEpoch (a soundness-review finding)");
    }
    binding = r0.configuredStartEpoch;
  }
  const subjects = new Map();
  let seenFirstHeaderWA = false;
  let firstHeaderBinding = null;
  let latestLag = null;

  const subjState = (key) => {
    if (!subjects.has(key)) {
      subjects.set(key, { gens: new Map(), stopped: false, decisions: [],
        watch: null, loopClosed: false, lastRecordIndex: -1, lastRecord: null,
        supersessions: new Map() });
    }
    return subjects.get(key);
  };
  const genState = (s, gen) => {
    if (!s.gens.has(gen)) s.gens.set(gen, { W: null, S: [], terminal: null, nonterminal: [], J: null,
      established: new Set() });
    return s.gens.get(gen);
  };
  const currentGen = (s) => (s.gens.size === 0 ? 0 : Math.max(...s.gens.keys()));

  records.forEach((r, i) => {
    validateJournalRecord(r, i, poolId, i === 0, seenFirstHeaderWA);
    const isCapture = r.kind === CAP_HEADER || r.kind === CAP_RECEIPT;
    const isSupersession = r.kind === SUPERSESSION_KIND;
    const key = subjectKey(r);
    const s = subjState(key);
    if (s.stopped && (STATE_BEARING.has(r.kind) || r.kind === K.DECISION)) {
      refuse(`a record follows a consumed stop on ${key} (stop is terminal and unsupersedable)`, i);
    }
    const noteRecord = () => { s.lastRecordIndex = i; s.lastRecord = r; };

    if (r.kind === K.DECISION) {
      const cg = currentGen(s) || 1;
      if (BROADCAST_OBJECTS.includes(r.object) && r.gen !== cg) {
        refuse(`a decision must act on its subject's current generation (${cg}, got ${r.gen})`, i);
      }
      const g = genState(s, r.gen);
      // exact-class evidence IN THIS GENERATION (checker finding 3)
      if (!g.established.has(r.condition)) {
        refuse(`decision carries condition ${r.condition} without its establishing evidence in generation ${r.gen}`, i);
      }
      for (const d of s.decisions) {
        if (!d.consumed && d.record.action !== "stop" && d.record.condition === r.condition) d.superseded = true;
      }
      const entry = { record: r, consumed: false, superseded: false, index: i };
      if (["stop", "keep-waiting", "observe-foreign", "continue-degraded"].includes(r.action)) {
        entry.consumed = true;
        if (r.action === "stop") s.stopped = true;
      }
      s.decisions.push(entry);
      noteRecord();
      return;
    }
    if (r.kind === K.DECLARATION) {
      if (r.condition === "lag-measurement") latestLag = r;
      const g = genState(s, r.gen); // a declaration OPENS generation state (finding 5)
      if (DECLARATION_CONDITIONS.includes(r.condition)) {
        g.established.add(r.condition);
      } else {
        // a SURFACING declaration: exact-class evidence in the CURRENT generation
        const cg = BROADCAST_OBJECTS.includes(r.object) ? currentGen(s) : 1;
        if (cg === 0) refuse(`surfacing ${r.condition} with no records on its subject`, i);
        if (BROADCAST_OBJECTS.includes(r.object) && r.gen !== cg) {
          refuse(`a surfacing declaration must name its subject's current generation`, i);
        }
        const gg = genState(s, cg);
        const evid = {
          "header-refused": gg.terminal && gg.terminal.kind === K.ERROR,
          "reservation-refused": gg.terminal && gg.terminal.kind === K.ERROR,
          "transfer-refused": gg.terminal && gg.terminal.kind === K.ERROR,
          "record-write-refused": gg.terminal && gg.terminal.kind === K.ERROR,
          "header-unresolved": gg.S.length > 0,
          "reservation-unresolved": gg.S.length > 0,
          "transfer-unresolved": gg.S.length > 0,
          "observation-unresolved": s.watch !== null && !s.loopClosed,
          // NO PRIOR EVIDENCE REQUIRED, deliberately: the document-write
          // loop journals nothing on an ambiguous outcome (it re-enters at
          // fetch), so the patience-expiry surfacing may be the subject's
          // FIRST record (the condition table's "error or first record"
          // row), and a second expiry after keep-waiting must also pass.
          // The prior form (s.gens.size > 0) was decoration, vacuously true
          // once this declaration's own genState ran (fold re-check F5)
          "record-write-unresolved": true,
          "header-foreign": gg.nonterminal.some((n) => n.kind === K.OBSERVATION && n.observationType === "foreign-document"),
          // the degraded continuation needs the proved result to BE this
          // branch's expected header: the observation's document identifier
          // must equal the write-ahead's expected one and the seven fields
          // must equal the expected contents (a proved MISMATCH establishes
          // header-foreign below, never the degraded continuation; the
          // distribution fold re-check found the weaker any-proved-route
          // form let a foreign header unlock it)
          "header-capture-incomplete": gg.nonterminal.some((n) => n.kind === K.OBSERVATION
            && n.observationType === "foreign-document" && n.route === PROVED_HEADER_ROUTE
            && gg.W && n.observedDocumentId === gg.W.expectedDocumentId
            && n.observedFields && typeof n.observedFields === "object"
            && ["poolId", "epochIndex", "grossCredits", "feeCredits", "allocationHash",
              "memberCount", "calcVersion"].every((k) => n.observedFields[k] === gg.W.expectedContents[k])),
          "reservation-foreign": gg.nonterminal.some((n) => n.kind === K.OBSERVATION && n.observationType === "foreign-claim"),
        }[r.condition];
        if (!evid) refuse(`surfacing declaration for ${r.condition} without its exact establishing evidence`, i);
        gg.established.add(r.condition);
      }
      noteRecord();
      return;
    }
    if (isSupersession) {
      // chain-validated HERE (checker finding 7): exact capture predecessor,
      // immutable hashes, contiguous unique seq per candidate key
      const g = s.gens.get(r.gen);
      const cap = g && g.terminal && (g.terminal.kind === CAP_HEADER || g.terminal.kind === CAP_RECEIPT)
        ? g.terminal : null;
      if (!cap) refuse("a supersession precedes the capture of its candidate key", i);
      if (r.supersededKind !== cap.kind) refuse("supersededKind disagrees with the capture", i);
      if (cap.kind === CAP_RECEIPT && r.accrualId !== cap.accrualId) refuse("supersession accrual disagrees", i);
      if (r.transitionHash !== cap.transitionHash) refuse("supersession transitionHash disagrees with the capture (content is immutable)", i);
      if (r.preimageHash !== preimageDigest(cap)) refuse("supersession preimageHash disagrees with the recomputed preimage", i);
      const seen = s.supersessions.get(r.gen) || 0;
      if (r.seq !== seen + 1) refuse(`supersession seq must be unique and contiguous from 1 (got ${r.seq} after ${seen})`, i);
      s.supersessions.set(r.gen, seen + 1);
      noteRecord();
      return;
    }

    const gen = r.gen;
    if (r.kind === K.WRITE_AHEAD) {
      if (["header", "reservation"].includes(r.object)) {
        if (gen > 1) {
          if (!s.gens.has(gen - 1)) refuse(`generation jump on ${key}`, i);
          const wanted = r.object === "header" ? "rebuild-corrected" : "rebuild-reservation";
          const cg = currentGen(s);
          if (gen !== cg + 1) refuse(`a new generation must follow the current one (${cg})`, i);
          const d = s.decisions.find((x) => !x.consumed && !x.superseded
            && x.record.action === wanted && x.record.gen === gen - 1);
          if (!d) refuse(`a gen-${gen} writeAhead on ${key} has no unconsumed ${wanted} decision at gen ${gen - 1}`, i);
          d.consumed = true;
        }
      } else if (gen !== 1) refuse("a transfer has exactly one generation in conformance", i);
      const g = genState(s, gen);
      if (g.W) refuse(`a second writeAhead in one generation on ${key}`, i);
      if (g.terminal) refuse("a writeAhead after the generation's terminal outcome", i);
      if (r.object === "reservation") {
        const tKey = subjectKey({ object: "transfer", poolId: r.poolId, epochIndex: r.epochIndex, accrualId: r.accrualId });
        const tW = subjects.get(tKey)?.gens.get(1)?.W;
        if (!tW) refuse("a reservation writeAhead precedes its transfer writeAhead", i);
        if (r.boundTransferHash !== tW.transitionHash) refuse("the reservation's boundTransferHash disagrees with the transfer writeAhead", i);
      }
      if (r.object === "header" && "configuredStartEpoch" in r) {
        seenFirstHeaderWA = true;
        firstHeaderBinding = r.configuredStartEpoch;
      }
      g.W = r;
      noteRecord();
      return;
    }
    if (r.kind === K.SENT_MARKER) {
      const g = s.gens.get(gen);
      if (!g || !g.W) refuse(`a sentMarker without its writeAhead on ${key}`, i);
      if (g.terminal) refuse("a sentMarker after the terminal outcome", i);
      if (r.transitionHash !== g.W.transitionHash) refuse("sentMarker hash disagrees with the writeAhead", i);
      if (r.object === "reservation") {
        const tKey = subjectKey({ object: "transfer", poolId: r.poolId, epochIndex: r.epochIndex, accrualId: r.accrualId });
        const tW = subjects.get(tKey)?.gens.get(1)?.W;
        if (!tW || g.W.boundTransferHash !== tW.transitionHash) {
          refuse("the reservation sentMarker's bound-transfer equality re-check failed", i);
        }
      }
      if (r.object === "transfer") {
        const rKey = subjectKey({ object: "reservation", poolId: r.poolId, epochIndex: r.epochIndex, accrualId: r.accrualId });
        const rs = subjects.get(rKey);
        const rg = rs?.gens.get(currentGen(rs));
        const chainOk = rg && rg.W && rg.S.length > 0 && rg.J
          && rg.J.boundTransferHash === g.W.transitionHash;
        if (!chainOk) refuse("a transfer sentMarker without the reservation's valid W-S-J holder chain (authority minting)", i);
        if (g.S.length > 0) {
          // the authorizing decision must be the subject's IMMEDIATELY
          // PRECEDING record (checker finding 3, the adjacency rule)
          const last = s.lastRecord;
          const d = s.decisions.find((x) => !x.consumed && !x.superseded
            && x.record.action === "rebroadcast-identical" && x.record === last);
          if (!d) refuse("a repeated transfer sentMarker must immediately follow its consumed rebroadcast-identical decision", i);
          d.consumed = true;
        }
      } else if (g.S.length > 0) refuse(`a repeated sentMarker on ${key}`, i);
      g.S.push(r);
      noteRecord();
      return;
    }
    if (r.kind === K.RESERVATION_SUCCESS) {
      const g = s.gens.get(gen);
      if (!g || g.S.length === 0) refuse("a reservationSuccess without its sentMarker", i);
      if (g.terminal) refuse("J after the generation's terminal outcome (the W-S-error-J sequence)", i);
      if (r.transitionHash !== g.W.transitionHash) refuse("J attempt hash disagrees with the writeAhead", i);
      if (r.boundTransferHash !== g.W.boundTransferHash) refuse("J boundTransferHash disagrees with the writeAhead", i);
      const tKey = subjectKey({ object: "transfer", poolId: r.poolId, epochIndex: r.epochIndex, accrualId: r.accrualId });
      const tW = subjects.get(tKey)?.gens.get(1)?.W;
      if (!tW || r.boundTransferHash !== tW.transitionHash) refuse("J boundTransferHash disagrees with the transfer writeAhead", i);
      g.terminal = r; g.J = r;
      noteRecord();
      return;
    }
    if (r.kind === K.ERROR) {
      const g = genState(s, gen);
      if (BROADCAST_OBJECTS.includes(r.object)) {
        if (g.S.length === 0) refuse(`an error on ${r.object} precedes its sentMarker`, i);
        if (r.errorClass === "execution-refusal") {
          if (g.terminal) refuse("a second terminal outcome in one generation", i);
          g.terminal = r;
          g.established.add(`${r.object}-refused`);
        } else {
          if (g.terminal) refuse("a nonterminal error after the terminal outcome", i);
          g.nonterminal.push(r);
        }
      } else {
        if (r.errorClass === "execution-refusal") {
          if (g.terminal) refuse("a second terminal outcome on a document-write subject", i);
          g.terminal = r;
          g.established.add("record-write-refused");
        } else g.nonterminal.push(r);
      }
      noteRecord();
      return;
    }
    if (r.kind === K.OBSERVATION) {
      const g = genState(s, gen);
      // every observation is evidence ABOUT A JOURNALED ATTEMPT: the
      // generation's writeAhead must exist (the fold re-check's F3 residue,
      // where genState creation let evidence and the decisions it feeds
      // exist in a generation with no attempt), and a claimed target hash
      // must equal that writeAhead's, never taken on faith
      if (!g.W) refuse("an observation on a generation with no writeAhead", i);
      if ("targetTransitionHash" in r && r.targetTransitionHash !== g.W.transitionHash) {
        refuse("the observation's targetTransitionHash disagrees with the generation's writeAhead", i);
      }
      if (r.observationType === "foreign-claim"
        && r.observedBoundTransferHash === g.W.boundTransferHash) {
        refuse("a foreign-claim's observed binding must differ from this branch's own boundTransferHash (an equal claim is the wait-only path, never foreign)", i);
      }
      // the observation LOOP is a closed machine on transfer subjects
      // (checker finding 4): one watch, one closing receipt-observed
      if (r.observationType === "watch-open") {
        if (g.terminal) refuse("a watch-open after the terminal outcome", i);
        if (s.watch) refuse("a second watch-open on one subject and branch", i);
        if (s.loopClosed) refuse("a watch-open after the loop closed", i);
        s.watch = r;
      } else if (r.observationType === "receipt-observed") {
        if (!s.watch) refuse("receipt-observed without a prior watch-open", i);
        if (s.loopClosed) refuse("a second receipt-observed (the loop is closed)", i);
        if (g.terminal) refuse("receipt-observed after a terminal outcome", i);
        s.loopClosed = true;
      } else if (g.terminal) {
        refuse("an observation after the terminal outcome", i);
      }
      g.nonterminal.push(r);
      noteRecord();
      return;
    }
    if (isCapture) {
      const g = s.gens.get(gen);
      if (!g || g.S.length === 0) refuse("a capture precedes its sentMarker", i);
      if (g.terminal) refuse("a capture after the generation's terminal outcome", i);
      // the capture REPRODUCES the write-ahead's persisted content
      // (finding 2). Bytes equality is IMPLIED here rather than checked
      // twice: validateCaptureShape has already recomputed the capture's
      // hash from its own bytes, line 167 did the same for the writeAhead,
      // so hash equality binds the bytes and a separate bytes check is
      // operationally redundant (redundant under SHA-256 collision
      // resistance, which every digest binding here already assumes)
      if (r.transitionHash !== g.W.transitionHash) refuse("capture hash disagrees with the writeAhead", i);
      if (r.kind === CAP_HEADER) {
        if (r.expectedDocumentId !== g.W.expectedDocumentId) refuse("capture expectedDocumentId disagrees with the writeAhead", i);
        if (canonicalString(r.expectedContents) !== canonicalString(g.W.expectedContents)) {
          refuse("capture expectedContents disagree with the writeAhead byte-for-byte", i);
        }
      }
      if (r.kind === CAP_RECEIPT) {
        const rKey = subjectKey({ object: "reservation", poolId: r.poolId, epochIndex: r.epochIndex, accrualId: r.accrualId });
        const rs = subjects.get(rKey);
        const rg = rs?.gens.get(currentGen(rs));
        if (!(rg && rg.J && rg.J.boundTransferHash === g.W.transitionHash)) {
          refuse("a receipt capture without the holder chain", i);
        }
      }
      g.terminal = r;
      noteRecord();
      return;
    }
    refuse(`unhandled kind ${r.kind}`, i);
  });

  if (binding !== null && firstHeaderBinding !== null && binding !== firstHeaderBinding) {
    refuse(`the configured-start binding disagrees across records (first record ${binding}, first header ${firstHeaderBinding}; a soundness-review finding)`);
  }

  // ---- the CLOSED READ RESULT, at its honest journal-local width: a
  // successful document write leaves NO journal record by contract, so
  // written accruals and parts are not enumerable here; the result carries
  // the expected numbers, broadcast states, capture flags, and the error and
  // stop states of every subject the journal HAS seen, which is exactly what
  // the admission consumer's conservative memberCount-based formula needs
  // (checker finding 6 narrowed and completed this shape) ----
  const perEpoch = {};
  const epochOf = (epoch) => {
    if (!perEpoch[epoch]) perEpoch[epoch] = { header: null, accruals: {}, documentWriteSubjects: {} };
    return perEpoch[epoch];
  };
  for (const [key, s] of subjects) {
    const [object, , epochStr, accrualId, partIndex] = key.split("|");
    if (object === "pool" || object === "epoch") continue;
    const epochIndex = Number(epochStr);
    const cg = currentGen(s) || 1;
    const g = s.gens.get(cg) || { W: null, S: [], terminal: null };
    const state = g.terminal
      ? (g.terminal.kind === K.ERROR ? "refused"
        : g.terminal.kind === K.RESERVATION_SUCCESS ? "held" : "captured")
      : g.S.length > 0 ? "sent" : g.W ? "written" : "annotated";
    const entry = { gen: cg, state, stopped: s.stopped };
    const e = epochOf(epochIndex);
    if (object === "header") {
      e.header = { ...entry,
        memberCount: g.W ? g.W.expectedContents.memberCount : null,
        grossCredits: g.W ? g.W.expectedContents.grossCredits : null,
        feeCredits: g.W ? g.W.expectedContents.feeCredits : null,
        captureIncomplete: [...s.gens.values()].some((x) => x.established && x.established.has("header-capture-incomplete")) };
    } else if (object === "reservation" || object === "transfer") {
      if (!e.accruals[accrualId]) e.accruals[accrualId] = {};
      e.accruals[accrualId][object] = entry;
      if (object === "transfer") {
        e.accruals[accrualId].receiptCaptured = !!(g.terminal && g.terminal.kind === CAP_RECEIPT);
        e.accruals[accrualId].observedByBranch = s.loopClosed;
      }
    } else {
      // accrual, part, receipt: journal-visible only via errors/declarations
      const dkey = partIndex !== "" ? `${object}:${accrualId}:${partIndex}` : `${object}:${accrualId}`;
      e.documentWriteSubjects[dkey] = entry;
    }
  }
  return {
    poolId,
    configuredStartEpoch: binding,
    // the highest epoch ANY record names, epoch-scoped declarations
    // included (perEpoch excludes pool and epoch subjects, so a consumer
    // bounding by it alone would miss a zero-earning declaration's epoch;
    // the admission's ascending check reads THIS field); null when no
    // record carries an epochIndex
    highestEpochIndex: records.reduce((m, r) =>
      (Number.isSafeInteger(r.epochIndex) && (m === null || r.epochIndex > m)) ? r.epochIndex : m, null),
    latestLagMeasurement: latestLag ? { lagCount: latestLag.lagCount,
      undistributedCredits: latestLag.undistributedCredits } : null,
    perEpoch,
  };
};

// the COMPOSED operation consumers use for action decisions: the raw store
// functions stay exported for tooling but are unsafe alone (checker finding
// 10), because nothing else guarantees the full committed array passed
// through semantic validation
const openValidatedJournal = (poolId, dir) => {
  const { records, committedOffset, journalFile } = openJournal(poolId, dir);
  const result = validateJournal(poolId, records);
  return { ...result, committedOffset, journalFile, records };
};

module.exports = { validateJournal, openValidatedJournal, K, ACTIONS,
  DECISION_CONDITIONS, DECLARATION_CONDITIONS, PROVED_HEADER_ROUTE };
