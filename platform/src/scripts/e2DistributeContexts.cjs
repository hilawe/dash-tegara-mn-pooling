/**
 * THE DISTRIBUTION DRIVER'S PER-EPOCH CONTEXTS (the per-epoch context design's step 7, the F3
 * refactor), built once per run and frozen.
 *
 * WHAT A CONTEXT IS. One immutable object holding everything the driver needs to do ONE epoch's
 * work: that epoch's figures, its entitlement rows with their document identities, the lookup
 * from accrual identifier back to row, and the identifier helper bound to that epoch. A context
 * closes over no other epoch's values, which is the whole point: the driver used to hold one
 * epoch index, one figures object and one row map for the length of the run, so a second epoch
 * would have inherited the first one's numbers with nothing to notice.
 *
 * WHAT IT DELIBERATELY DOES NOT HOLD. Anything the ledger served. Observed state belongs to the
 * evidence bundle and the step results, never here, and the design's independence column is the
 * rule: every field below is computed before any epoch-record query is issued and from no
 * epoch-record document. The journal is a trusted local input, the writer's own record of what it
 * committed, and the figures come from it on the resume path.
 *
 * THE CARRY RECURSION IS THE REASON THE EPOCHS ARE BUILT TOGETHER rather than one at a time. An
 * epoch's effective rows depend on what the epochs below it could not pay, so the calculation is
 * handed the WHOLE RUN and each context takes its own slice. Building one context per call would
 * give each epoch a fresh calculation with a zero carry-in, which is correct only for the first.
 */
const docId = require("./e2DocId.cjs");
const entitlementCalc = require("./entitlementCalc.cjs");

const HEX64 = /^[0-9a-f]{64}$/;
const refuse = (m) => { throw new Error(`e2DistributeContexts: ${m}`); };

// a figures object as the journal's header write-ahead carries it, checked at the width the
// driver actually consumes; allocationHash is nullable because a bootstrap run fills it from the
// proved resolution after this point, and a null there is a stated hole rather than a silent one
const FIGURE_INTEGERS = ["grossCredits", "feeCredits"];
const validateFigures = (f, n) => {
  if (!f || typeof f !== "object") refuse(`epoch ${n} carries no figures object`);
  for (const k of FIGURE_INTEGERS) {
    const v = f[k];
    const ok = (typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v))
      || (typeof v === "number" && Number.isSafeInteger(v) && v >= 0)
      || (typeof v === "bigint" && v >= 0n);
    if (!ok) refuse(`epoch ${n}'s ${k} is ${JSON.stringify(String(v))}, not a nonnegative integer`);
  }
  if (BigInt(f.feeCredits) > BigInt(f.grossCredits)) {
    refuse(`epoch ${n}'s fee ${f.feeCredits} exceeds its gross ${f.grossCredits}`);
  }
  if (!Number.isSafeInteger(f.memberCount) || f.memberCount < 0) {
    refuse(`epoch ${n}'s memberCount is ${JSON.stringify(f.memberCount)}, not a nonnegative integer`);
  }
  if (f.allocationHash !== null && !(typeof f.allocationHash === "string" && HEX64.test(f.allocationHash))) {
    refuse(`epoch ${n}'s allocationHash is neither null nor 64 lowercase hex`);
  }
  return f;
};

// THE RUN'S EPOCH LIST, checked as a list rather than one entry at a time: the carry recursion is
// defined over a CONSECUTIVE run beginning at the configured start, so a gap or a repeat is not a
// run the calculation can answer for, and a descending list is not one either
const validateEpochList = (epochs, configuredStart) => {
  if (!Array.isArray(epochs) || epochs.length === 0) refuse("the run covers no epochs");
  const numbers = epochs.map((e, i) => {
    if (!e || !Number.isSafeInteger(e.number) || e.number < 0) refuse(`run entry ${i} carries no nonnegative integer epoch number`);
    return e.number;
  });
  for (let i = 1; i < numbers.length; i++) {
    if (numbers[i] !== numbers[i - 1] + 1) {
      refuse(`the run is ${numbers.join(",")}, which is not consecutive; the carry recursion is defined over a consecutive run and cannot answer across a gap or a repeat`);
    }
  }
  if (!Number.isSafeInteger(configuredStart) || configuredStart < 0) {
    refuse(`the configured start ${JSON.stringify(configuredStart)} is not a nonnegative integer; the carry recursion has no base`);
  }
  if (numbers[0] !== configuredStart) {
    refuse(`the run begins at epoch ${numbers[0]} while the configured start is ${configuredStart}; a run beginning above its base computes from a carry nobody established`);
  }
  return numbers;
};

/**
 * buildContexts({ poolId, configuredStart, epochs, allocation, owners, incomeIdentity,
 *                 encodingCeiling, identifiers })
 *
 * `epochs` is [{ number, figures }] for the whole run, consecutive and beginning at the
 * configured start. `identifiers` is { generateId, ownerId, contractId }, the derivation's
 * injected pieces, so this module needs no platform client. `owners` carries the display fields
 * the driver attaches to each row, one entry per allocation recipient.
 *
 * Returns { epochNumbers, contextFor(n), has(n) }. contextFor REFUSES an epoch outside the run
 * rather than answering, because an epoch the calculation never covered has no carry state and an
 * answer for it would be arithmetic over a base that does not exist.
 */
const buildContexts = ({ poolId, configuredStart, epochs, allocation, owners, incomeIdentity,
  encodingCeiling, identifiers }) => {
  if (typeof poolId !== "string" || !HEX64.test(poolId)) refuse(`poolId ${JSON.stringify(poolId)} is not 64 lowercase hex`);
  if (!identifiers || typeof identifiers.generateId !== "function") refuse("buildContexts needs identifiers.generateId");
  if (identifiers.ownerId === undefined || identifiers.contractId === undefined) refuse("buildContexts needs identifiers.ownerId and identifiers.contractId");
  if (!Array.isArray(owners) || owners.length === 0) refuse("buildContexts needs the owner list");
  const numbers = validateEpochList(epochs, configuredStart);
  for (const e of epochs) validateFigures(e.figures, e.number);

  // ONE calculation over the WHOLE run, so the carry threads between epochs
  const calc = entitlementCalc.buildCarryCapableEntitlements({
    incomeIdentity,
    encodingCeiling,
    configuredStart,
    allocation,
    epochs: epochs.map((e) => ({ number: e.number,
      distributableCredits: String(BigInt(e.figures.grossCredits) - BigInt(e.figures.feeCredits)) })),
  });

  const docIdForIn = (epochIndex, type, subject) => docId.docIdForIn({
    generateId: identifiers.generateId, ownerId: identifiers.ownerId, contractId: identifiers.contractId,
    poolId, epochIndex, type, subject });

  const built = new Map();
  for (const e of epochs) {
    const n = e.number;
    const rows = calc.rowsFor(n).map((er) => {
      const o = owners.find((x) => x.funderHex === er.recipientId);
      if (!o) refuse(`epoch ${n}'s calculation answered recipient ${String(er.recipientId).slice(0, 12)}..., which is not in the owner list`);
      const acc = docIdForIn(n, "platformAccrual", er.recipientId);
      return Object.freeze({ ...er, accrualId: acc.hex, accrualIdB58: acc.b58, accrualEntropy: acc.entropy,
        funderHex: er.recipientId, bps: o.bps, recipientB58: o.recipientB58 });
    });
    const byAccrual = new Map(rows.map((r) => [r.accrualId, r]));
    if (byAccrual.size !== rows.length) refuse(`epoch ${n} produced two rows under one accrual identifier`);
    built.set(n, Object.freeze({
      epochIndex: n,
      figures: Object.freeze({ ...e.figures }),
      rows: Object.freeze(rows),
      rowFor: (accrualId) => byAccrual.get(accrualId),
      // the identifier helper BOUND TO THIS EPOCH, so a caller holding one context cannot
      // derive another epoch's identity through it by accident
      docIdFor: (type, subject) => docIdForIn(n, type, subject),
    }));
  }

  return Object.freeze({
    epochNumbers: Object.freeze([...numbers]),
    has: (n) => built.has(n),
    contextFor: (n) => {
      const c = built.get(n);
      if (!c) refuse(`epoch ${JSON.stringify(n)} is outside this run (${numbers.join(",")}); the calculation never covered it, so it carries no state to answer from`);
      return c;
    },
  });
};

/**
 * parseDeclaredFigures(raw, firstEpoch, baseFigures) -> [{ number, figures }] ascending
 *
 * The epochs ABOVE the run's first take their income figures from an explicit declaration, the
 * same convention the forward transport runner uses. `raw` is a JSON object keyed by epoch
 * number, each value carrying `grossCredits` and `feeCredits` and nothing else that matters.
 *
 * ONLY THE INCOME FIGURES ARE DECLARABLE. The member count, the calculation version and the
 * allocation hash are inherited from the base figures, because they describe the POOL rather than
 * the epoch, and a declaration able to restate them could put a run's rows under an allocation
 * the formation never agreed. An empty declaration is a one-epoch run, which is what this driver
 * did before it could do more.
 */
/**
 * declaredShape(raw, firstEpoch) -> [{ number, grossCredits, feeCredits }] ascending
 *
 * THE SHAPE CHECK ALONE, so it can run BEFORE anything is read or written. It needs only the
 * run's first epoch, which is known from the gate artifact, while the full parse needs the base
 * figures, which are known only after the pool has been resolved or formed. The review found that
 * a declaration naming an epoch across a gap refused only after the opening balance reads and,
 * on a bootstrap run, after a pool had already been formed. Everything a malformed declaration
 * can be caught on is checked here.
 */
const declaredShape = (raw, firstEpoch) => {
  if (raw === undefined || raw === null || raw === "") return [];
  if (typeof raw !== "string") refuse("the declared figures must be given as JSON text");
  if (!Number.isSafeInteger(firstEpoch) || firstEpoch < 0) refuse(`the run's first epoch ${JSON.stringify(firstEpoch)} is not a nonnegative integer`);
  let parsed;
  try { parsed = JSON.parse(raw); } catch (e) { refuse(`the declared figures are not JSON (${(e && e.message) || String(e)})`); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    refuse("the declared figures must be a JSON object keyed by epoch number");
  }
  const entries = Object.entries(parsed).map(([k, v]) => {
    if (!/^(0|[1-9][0-9]*)$/.test(k)) refuse(`the declared figures carry the key ${JSON.stringify(k)}, which is not a canonical epoch number`);
    const number = Number(k);
    if (!Number.isSafeInteger(number)) refuse(`the declared epoch ${k} is not a safe integer`);
    if (number <= firstEpoch) refuse(`the declared figures name epoch ${number}, which is at or below the run's first epoch ${firstEpoch}; the first epoch's figures come from the journal or the bootstrap fixture, never from a declaration`);
    if (v === null || typeof v !== "object") refuse(`the declaration for epoch ${number} is not an object`);
    const toCredits = (rawAmount, name) => {
      const ok = (typeof rawAmount === "string" && /^(0|[1-9][0-9]*)$/.test(rawAmount))
        || (typeof rawAmount === "number" && Number.isSafeInteger(rawAmount) && rawAmount >= 0);
      if (!ok) refuse(`the declaration for epoch ${number} carries ${name}=${JSON.stringify(rawAmount)}, which is not a canonical nonnegative integer`);
      const n = Number(rawAmount);
      if (!Number.isSafeInteger(n)) refuse(`the declaration for epoch ${number} carries ${name}=${JSON.stringify(rawAmount)}, which is above the schema's credit ceiling`);
      return n;
    };
    return { number, grossCredits: toCredits(v.grossCredits, "grossCredits"), feeCredits: toCredits(v.feeCredits, "feeCredits") };
  }).sort((a, b) => a.number - b.number);
  for (let i = 0; i < entries.length; i++) {
    const want = firstEpoch + 1 + i;
    if (entries[i].number !== want) {
      refuse(`the declared epochs are ${entries.map((e) => e.number).join(",")}, which do not continue consecutively from the run's first epoch ${firstEpoch}; the carry recursion cannot answer across a gap`);
    }
  }
  return entries;
};

const parseDeclaredFigures = (raw, firstEpoch, baseFigures) => {
  const shape = declaredShape(raw, firstEpoch);
  if (shape.length === 0) return [];
  validateFigures(baseFigures, firstEpoch);
  // the pool's own members are inherited, never declared: they describe the POOL rather than the
  // epoch, and a declaration able to restate them could put a run's rows under an allocation the
  // formation never agreed
  return shape.map(({ number, grossCredits, feeCredits }) => {
    const figures = { grossCredits, feeCredits,
      memberCount: baseFigures.memberCount, calcVersion: baseFigures.calcVersion,
      allocationHash: baseFigures.allocationHash };
    validateFigures(figures, number);
    return { number, figures };
  });
};

module.exports = { buildContexts, validateFigures, validateEpochList, declaredShape, parseDeclaredFigures };
