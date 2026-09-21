/**
 * THE POOL RESOLUTION'S DECISIONS, extracted from the distribution runner so a battery can drive
 * them.
 *
 * WHY. An independent review removed the single-document cardinality check from the runner's
 * proved fetch and watched the entire dependency battery stay green, because `resolvePool` was
 * injected into that module as if it were transport when what it carries is a stack of refusals.
 * The dependency factory's own header named this as the next unit of the same class and said it
 * was not addressed there. This is that unit.
 *
 * WHAT IT DECIDES, each of which refuses by name:
 *   - CARDINALITY: a proved read answering with other than exactly one document resolves nothing.
 *   - SUBJECT: the document served must BE the pool that was asked for, not merely a pool.
 *   - PAIRING: the pool and its completion receipt pass the six-duty pair check.
 *   - ELIGIBILITY: the node type is the one the predicate admits.
 *   - ALLOCATION INTEGRITY: the recomputed allocation hash equals the receipt's stored one.
 *   - OWNERSHIP: the allocation carries at least one owner.
 *     THOSE TWO ARE DEFENCE IN DEPTH RATHER THAN INDEPENDENTLY REACHABLE REFUSALS. A review
 *     executed both against the REAL pair checker and found each case refused EARLIER, at the
 *     pair check, so neither local rule fires in production today. The battery reaches them by
 *     injecting a passing verdict, which establishes conditional behaviour and not a production
 *     path. They stay because a pair checker that stops covering either property would otherwise
 *     leave nothing behind it, and that is what the comment claims, no more.
 *   - QUANTIFICATION: entitlement rows are refused without the epoch's journaled header numbers.
 *   - RUN MEMBERSHIP: an epoch outside the run its journal evidences is refused here with the
 *     range named. The calculation refuses it independently, so this is the earlier diagnostic
 *     rather than the sole prevention, and the battery pins that distinction.
 *   - FIGURE RECONCILIATION: gross and fee are compared FIELD BY FIELD, never through the amount
 *     they derive to, because 1000/10 and 1100/110 agree on 990 and on nothing else.
 *   - ATTESTATION: a journal with no proved resolution REFUSES the admission rather than
 *     answering that it owes nobody anything (a soundness-review finding).
 *   - OWNER IDENTITY: every allocation owner resolves, is the subject asked for, and passes pins.
 *
 * WHAT STAYS OUTSIDE. The transport: the proof-verifying query, the identity lookup route, the
 * journal's filesystem, the identifier generator. Those are injected, and the CHECKS ON THEIR
 * ANSWERS live here. The split is the same one the dependency factory uses, and it is the reason
 * that factory could be driven at all.
 *
 * WHAT THIS MODULE DOES NOT ESTABLISH. It performs no proof verification itself. Its proved
 * reads are whatever `provedQuery` gives it, and that function's marker check belongs to
 * `e2DistributeEpochDeps.makeProvedQuery`. Reaching a resolution here means every refusal below
 * declined to fire over the answers supplied, never that those answers were proved by this code.
 */
const formationCore = require("./formationCore.cjs");
const entitlementCalc = require("./entitlementCalc.cjs");

const refuse = (m) => { throw new Error(`e2PoolResolution: ${m}`); };

const plainOf = (doc) => (typeof doc.getProperties === "function" ? doc.getProperties() : doc.properties);
const ownerHexOfWith = (idHex) => (doc) => {
  const o = doc.getOwnerId ? doc.getOwnerId() : doc.ownerId;
  return idHex(o);
};

/**
 * EXACTLY ONE DOCUMENT, or nothing is resolved. A review deleted this check and watched the whole
 * dependency battery pass, because that battery injects the resolver as an opaque function and
 * never asks what it refuses. Two documents for one subject is an ambiguity, and choosing the
 * first is a decision no caller asked for.
 */
const makeProvedFetchOne = ({ provedQuery }) => {
  if (typeof provedQuery !== "function") refuse("makeProvedFetchOne needs provedQuery");
  return async (type, where, label) => {
    const docs = await provedQuery(type, where, label);
    if (!Array.isArray(docs)) refuse(`${label}: the proved read did not answer with a document list`);
    if (docs.length !== 1) throw new Error(`${label}: expected exactly one document, found ${docs.length}`);
    return docs[0];
  };
};

// THE PAIR CHECK IS INJECTED, not required here, and the reason is the defect this module was
// extracted to remove. What this module owns is the REFUSAL on the checker's verdict, and a
// refusal no case can reach is the shape every round of this project keeps finding. The checker
// itself is a shared component with its own tests (`receiptPoolCheckTest.cjs`); the runner wires
// the real one, and a battery can drive both sides of the verdict.
const RESOLVE_ENV = ["provedQuery", "contractId", "writerHex", "b58Of", "idHex",
  "encodingCeiling", "openJournalFor", "runFromJournal", "docIdForIn", "checkReceiptAgainstPool"];

/**
 * makeResolveProvedPool(env) -> async (pid) -> {
 *   resolved: true, writerIdentity, incomeIdentity, allocationHashHex, owners,
 *   entitlementsForEpoch(epochIndex, numbers) }
 *
 * ONE PROVED RESOLUTION PER REAL POOL, honoring the identifier it is asked for. A resolver that
 * ignores its argument answers wrongly the moment the store holds two pools, which bootstrap mode
 * makes the normal case.
 */
const makeResolveProvedPool = (env) => {
  if (!env || typeof env !== "object") refuse("makeResolveProvedPool needs its environment");
  for (const k of RESOLVE_ENV) {
    if (env[k] === undefined || env[k] === null) refuse(`makeResolveProvedPool needs env.${k}`);
  }
  const { contractId: V11, writerHex, b58Of, idHex, encodingCeiling,
    openJournalFor, runFromJournal, docIdForIn, checkReceiptAgainstPool } = env;
  const provedFetchOne = makeProvedFetchOne({ provedQuery: env.provedQuery });
  const ownerHexOf = ownerHexOfWith(idHex);

  return async (pid) => {
    const label = `pool ${pid.slice(0, 8)}...`;
    const poolDocP = await provedFetchOne("pool", [["$id", "==", b58Of(pid)]], `${label} record`);
    // THE SUBJECT, not merely a subject. A proved read that served a different pool has not
    // answered the question, and the pair check below would then compare the wrong pair.
    if (idHex(poolDocP.id) !== pid) {
      throw new Error(`${label}: the proved read returned a different document (${idHex(poolDocP.id).slice(0, 12)}...)`);
    }
    const receiptP = await provedFetchOne("completionReceipt",
      [["poolId", "==", Buffer.from(pid, "hex")]], `${label} completion receipt`);
    const pair = checkReceiptAgainstPool({
      contractId: V11, receipt: plainOf(receiptP), pool: plainOf(poolDocP),
      poolId: b58Of(pid),
      // 32-byte Buffers: the shape toId32 decodes unconditionally (a WASM identifier object's
      // own methods vary by construction path)
      receiptOwnerId: Buffer.from(ownerHexOf(receiptP), "hex"),
      poolOwnerId: Buffer.from(ownerHexOf(poolDocP), "hex") });
    if (!pair.ok) throw new Error(`${label}: the pool/receipt pair check refused: ${pair.reason}`);
    const poolProps = plainOf(poolDocP);
    if (poolProps.nodeType !== "evo") {
      throw new Error(`${label}: nodeType is ${JSON.stringify(poolProps.nodeType)}, not "evo" (the eligibility predicate)`);
    }
    const rp = plainOf(receiptP);
    const rehash = formationCore.allocationHash(Buffer.from(rp.allocationRows)).toString("hex");
    const storedHash = Buffer.from(rp.allocationHash).toString("hex");
    if (rehash !== storedHash) {
      throw new Error(`${label}: the recomputed allocation hash ${rehash.slice(0, 12)}... differs from the receipt's ${storedHash.slice(0, 12)}...`);
    }
    const alloc = JSON.parse(Buffer.from(rp.allocationRows).toString("utf8"));
    // ["tegara-completion-allocation", 1, contractId, poolId, target, [[owner, amountDuffs, bps, script], ...]]
    const poolOwners = alloc[5].map((row) => ({ ownerB58: row[0], bps: row[2] }));
    if (poolOwners.length < 1) throw new Error(`${label}: the allocation carries no owners`);
    const incomeIdentity = ownerHexOf(poolDocP);
    return {
      // THE ATTESTATION the admission requires (a soundness-review finding). Everything above this point is the
      // proved resolution: the pool and its completion receipt read through the proof-verifying
      // query with the verified-call marker checked, the six-duty pair check, the eligibility
      // predicate, the recomputed allocation hash. Reaching here IS the resolution, so this is
      // the one place entitled to claim it.
      resolved: true,
      writerIdentity: writerHex, // the configured contract owner, a stated width
      incomeIdentity,
      allocationHashHex: rehash,
      owners: poolOwners,
      // THE STORE-WIDE ADMISSION'S ROW SOURCE IS CARRY-CAPABLE. It used to be pre-carry, under a
      // stated width that was correct only while every resolved pool's run was one epoch at its
      // configured start. That width was a real exposure rather than a presentational one: the
      // income identity's funding requirement is SUMMED from these amounts, so a pre-carry figure
      // UNDER-RESERVES the moment any pool's run passes one epoch.
      //
      // THE RUN COMES FROM THE POOL'S OWN JOURNAL, the record of what the writer committed per
      // epoch, so the recursion gets the consecutive run it needs without asking the chain
      // anything. `runFromJournal` refuses a gap rather than skipping it.
      //
      // IT IS READ AT CALL TIME, not at resolution time, because headers are written while the
      // run proceeds and an admission consulting a stale run would answer about a journal that no
      // longer exists.
      entitlementsForEpoch: (epochIndex, numbers) => {
        if (!numbers || numbers.grossCredits === undefined || numbers.feeCredits === undefined) {
          throw new Error(`${label}: entitlement rows need the epoch's journaled header numbers; refusing an unquantified answer`);
        }
        const read = openJournalFor(pid);
        const epochs = runFromJournal(read);
        const mine = epochs.find((e) => e.number === epochIndex);
        // WHAT THIS REFUSAL IS FOR, stated at its real width (a review confirmed this reading).
        // It is NOT the only thing standing
        // between a caller and a wrong-epoch answer: the calculation below refuses an epoch
        // outside its run by its own rule, which the battery pins. What this buys is an EARLIER
        // and more specific diagnostic, naming the range the journal actually evidences.
        if (!mine) {
          throw new Error(`${label}: epoch ${epochIndex} carries obligation evidence but is outside the run its journal evidences (${epochs.length ? `${epochs[0].number}..${epochs[epochs.length - 1].number}` : "empty"}); its effective entitlements cannot be recomputed from a carry that never reached it`);
        }
        // THE TWO SOURCES OF THIS EPOCH'S FIGURES ARE RECONCILED FIELD BY FIELD, not through the
        // amount they happen to derive to. Comparing only gross minus fee accepts 1000/10 against
        // 1100/110, which agree on 990 and on nothing else, so a check on the derived value alone
        // would have called two different headers the same one.
        if (String(numbers.grossCredits) !== mine.grossCredits
          || String(numbers.feeCredits) !== mine.feeCredits) {
          throw new Error(`${label}: epoch ${epochIndex}'s journaled header reads gross=${mine.grossCredits} fee=${mine.feeCredits} in the run and gross=${numbers.grossCredits} fee=${numbers.feeCredits} in the numbers the admission passed; refusing rather than choosing one`);
        }
        if (numbers.memberCount !== undefined && numbers.memberCount !== mine.memberCount) {
          throw new Error(`${label}: epoch ${epochIndex}'s memberCount is ${mine.memberCount} in the run and ${numbers.memberCount} in the numbers the admission passed; refusing rather than choosing one`);
        }
        const calc = entitlementCalc.buildCarryCapableEntitlements({
          incomeIdentity,
          encodingCeiling,
          configuredStart: read.configuredStartEpoch,
          allocation: poolOwners.map((o) => ({ recipientId: idHex(o.ownerB58), bps: o.bps })),
          epochs });
        // THE OVER-CEILING REFUSAL lives in the calculation: buildCarryCapableEntitlements marks
        // a run refused from the epoch whose owed OR effective amounts exceed the ceiling, and
        // rowsFor throws for that epoch and every later one rather than returning rows.
        //
        // THE POSITIVE ROWS ONLY, which is this seam's documented contract
        return calc.rowsFor(epochIndex)
          .filter((r) => BigInt(r.amountCredits) > 0n)
          .map((r) => ({
            accrualId: docIdForIn(pid, epochIndex, "platformAccrual", r.recipientId).hex,
            amountCredits: r.amountCredits, recipientId: r.recipientId }));
      },
    };
  };
};

/**
 * THE RESOLVED-OR-NOT CLASSIFICATION (a soundness-review finding). A journal this run cannot resolve REFUSES the
 * admission; it does not answer with no entitlements. The old fallback assumed any unrecognized
 * journal was battery debris contributing nothing to the store-wide funding threshold, so a
 * journal whose header evidenced obligations was quantified as owing nobody anything. The
 * assumption was probably true of that store and was never established, which is the whole defect.
 *
 * THE REFUSAL NAMES THE POOL, so the operator learns which journal is unaccounted for rather than
 * getting a smaller reserve. The remedy is to keep probe journals out of the live admission store,
 * not to teach this function to guess again.
 */
const makePoolResolver = ({ resolvedPools, log }) => {
  if (!(resolvedPools instanceof Map)) refuse("makePoolResolver needs the resolved-pool map");
  if (typeof log !== "function") refuse("makePoolResolver needs an explicit log function");
  return (pid) => {
    if (resolvedPools.has(pid)) return resolvedPools.get(pid);
    log(`  [UNRESOLVED] store journal ${pid.slice(0, 12)}... has no proved resolution; the admission will refuse rather than quantify its obligations as zero (a soundness-review finding)`);
    return { resolved: false, unresolvedPoolId: pid };
  };
};

const OWNER_ENV = ["lookupIdentity", "idHex", "chainIdPin", "protocolPin"];

/**
 * EVERY ALLOCATION OWNER RESOLVES, IS THE SUBJECT ASKED FOR, AND PASSES THE PINS (a soundness-review finding). The
 * middle check is the one that is easy to omit: a lookup that answers with SOME identity has
 * proved a different subject, not this one.
 */
const makeVerifyAllocationOwners = (env) => {
  if (!env || typeof env !== "object") refuse("makeVerifyAllocationOwners needs its environment");
  for (const k of OWNER_ENV) {
    if (env[k] === undefined || env[k] === null) refuse(`makeVerifyAllocationOwners needs env.${k}`);
  }
  const { lookupIdentity, idHex, chainIdPin, protocolPin } = env;
  return async (owners) => {
    if (!Array.isArray(owners) || owners.length === 0) {
      refuse("verifyAllocationOwners needs at least one owner; an empty set would pass vacuously");
    }
    for (const o of owners) {
      const r = await lookupIdentity(o.ownerB58);
      if (!r || !r.identity) {
        throw new Error(`recipient identity ${o.ownerB58.slice(0, 8)}... did not resolve through the proved lookup (a soundness-review finding)`);
      }
      const gotId = idHex(typeof r.identity.id !== "undefined" ? r.identity.id
        : (typeof r.identity.getId === "function" ? r.identity.getId() : r.identity));
      if (gotId !== idHex(o.ownerB58)) {
        throw new Error(`the proved identity lookup for ${o.ownerB58.slice(0, 8)}... returned a different identity (${gotId.slice(0, 12)}...)`);
      }
      if (!r.metadata || r.metadata.chainId !== chainIdPin
        || Number(r.metadata.protocolVersion) !== protocolPin) {
        throw new Error(`the proved identity lookup fails the pins for ${o.ownerB58.slice(0, 8)}... (chain ${r.metadata && r.metadata.chainId}, protocol ${r.metadata && r.metadata.protocolVersion})`);
      }
    }
    return { checked: owners.length };
  };
};

/**
 * THE HEADER-TO-RECEIPT BINDING. The header figures' allocationHash and the proved receipt's
 * recomputed hash must be ONE value. Bootstrap TAKES it from the proved receipt; a resume REFUSES
 * a journaled header that disagrees with it. The owner count and the header's memberCount are the
 * same kind of agreement and refuse together.
 */
const bindHeaderToReceipt = ({ bootstrap, headerAllocationHash, headerMemberCount, target }) => {
  if (!target || target.resolved !== true) refuse("bindHeaderToReceipt needs a resolved target");
  if (!Array.isArray(target.owners)) refuse("bindHeaderToReceipt needs the target's owners");
  if (target.owners.length !== headerMemberCount) {
    throw new Error(`the allocation row count ${target.owners.length} differs from the header's memberCount ${headerMemberCount}`);
  }
  if (bootstrap) return { allocationHash: target.allocationHashHex, source: "proved-receipt" };
  if (headerAllocationHash !== target.allocationHashHex) {
    throw new Error(`the journaled header's allocationHash ${String(headerAllocationHash).slice(0, 12)}... differs from the proved receipt's recomputed ${target.allocationHashHex.slice(0, 12)}...`);
  }
  return { allocationHash: headerAllocationHash, source: "journaled-header" };
};

module.exports = { makeProvedFetchOne, makeResolveProvedPool, makePoolResolver,
  makeVerifyAllocationOwners, bindHeaderToReceipt, plainOf, ownerHexOfWith,
  RESOLVE_ENV, OWNER_ENV };
