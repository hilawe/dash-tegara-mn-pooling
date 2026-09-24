/**
 * THE PER-EPOCH DEPENDENCY FACTORY, extracted from the distribution runner so a battery can drive
 * the decisions it makes rather than recognizing their text in the runner's source.
 *
 * WHY. The working method's 2026-09-20 amendment says a runner may hold WIRING, and that anything
 * which DECIDES or ADAPTS moves to a module a battery can drive, because a review that can only
 * read a runner's text is being asked a question it cannot answer. Every one of the trial's three
 * milestones produced a finding of exactly that class, and this factory was the last one named:
 * it sat inline in `e2DistributeRun.mjs`, where no offline battery could reach it and a source
 * sweep stood in for one.
 *
 * WHAT IT DECIDES, which is what the battery drives:
 *   - the EXTENT discovery answers, which must be this run's epochs and no others;
 *   - WHICH CALCULATION FIELDS reach the writer, `carryInCredits` among them;
 *   - WHOSE FIGURES answer, which must be the context the bundle was built from;
 *   - the LIFECYCLE ANSWER, fail-closed over the run's own completed record;
 *   - the PROVED HEADER READ's refusals, on the marker, the count and the key asked for;
 *   - the NONCE PIN CHECKS on chain and protocol version;
 *   - the HEADER BUILD's refusals, on mode, on a missing prefetch and on an epoch mismatch;
 *   - ONCE-ONLY consumption of every prefetched nonce;
 *   - the UNIQUE LOGICAL BINDING each document type is recovered through.
 *
 * WHAT STAYS IN THE RUNNER, deliberately, and why the split is here rather than elsewhere. The
 * TRANSPORT stays: the dynamic SDK imports, the gRPC pool, the signing keys, the journal's
 * filesystem. Those are wiring, they are the runner's to hold, and holding them here is what used
 * to make this code undrivable, since a nonce reader that imports by absolute container path
 * cannot run outside the container. So the raw reads are INJECTED and the CHECKS ON THEIR ANSWERS
 * live here. A pin check is a decision; the gRPC call that produced the value it checks is not.
 *
 * ONE INJECTED MEMBER IS NOT TRANSPORT, and saying so is the point of naming it. `env.resolvePool`
 * is an adapter that still DECIDES, in the runner: single-document cardinality, the requested-pool
 * identity check, the eligibility predicate, the recomputed allocation-hash agreement, the
 * journal-derived entitlement selection, the resolved-versus-unresolved classification, and the
 * recipient identity and pin checks. A review removed its cardinality check and watched every
 * assertion in this module's battery stay green, which is the same blindness the extraction
 * removed here. It is the next unit of this class and is on the backlog, not addressed by this
 * module, so nothing here should be read as covering it.
 *
 * WHAT THIS MODULE DOES NOT ESTABLISH. `provedHeaderQuery` does not itself prove anything: it
 * refuses an answer that fails the marker, the count or the key, and the marker check belongs to
 * `makeProvedQuery` below. Nothing here verifies a signature or a proof; the module's own
 * guarantee ends at refusing an answer that does not attest, and that width is why the claim is
 * stated rather than left to the reader.
 *
 * THE ONE-IMPLEMENTATION CLAIM IS SCOPED TO THE DISTRIBUTION RUNNER, and the scope is stated
 * because the first draft of this header did not state it. Within `e2DistributeRun.mjs` both
 * callers of the proved read now reach this one function. They are not the only marker checks in
 * the repository: a sweep for the class on 2026-09-20 found `registerV11Run.mjs` carrying a
 * near-verbatim copy, `e2AuditRun.mjs` reading the marker at three sites, and
 * `e2ForwardTransportRun.mjs` holding both an inline pair and an injected reader, with inline
 * dependency bundles in four runners and inline nonce pin checks in two more. Those are the same
 * class as the extraction this module is, they are NOT addressed here, and they are on the
 * backlog rather than counted as done.
 */
const { nonceUsability } = require("./e2NonceWindow.cjs");
const docIdMod = require("./e2DocId.cjs");
const captureRecord = require("./e2CaptureRecord.cjs");
const battery = require("./e2CaptureBattery.cjs");
const rawCapture = require("./e2RawCapture.cjs");
const balanceCheckMod = require("./e2BalanceCheck.cjs");

const refuse = (m) => { throw new Error(`e2DistributeEpochDeps: ${m}`); };
const msgOf = (e) => (e && e.message) || String(e);

/**
 * THE PROVED DOCUMENT READ's marker check (a soundness-review finding). Every DOCUMENT QUERY in the distribution
 * runner that claims proof goes through here. The duplicate-header recovery used to issue its own
 * bare query, obtaining no proof and checking no marker, while the writer journaled the answer
 * under a route whose value says proved. Copying the check into a second place would have left two
 * implementations of one rule.
 *
 * THE SCOPE IS DOCUMENT QUERIES, and the earlier wording said "every read in the driver that
 * claims proof", which a review showed is wider than the truth. The identity and nonce reads
 * reach the ledger by their own routes and are checked by their own pins, not by this marker.
 *
 * IT IS A FUNCTION OVER AN INJECTED QUERY so a battery can drive it: the marker lives on
 * `globalThis`, set by the patched proof-verifying wrapper, and a case can set, clear or corrupt
 * it and watch what this decides. An unmarked answer REFUSES rather than being returned unlabelled.
 */
const makeProvedQuery = ({ query }) => {
  if (typeof query !== "function") refuse("makeProvedQuery needs a query function");
  return async (type, where, label) => {
    delete globalThis.__tegaraResponseMetadata;
    const docs = await query(type, where);
    if (!globalThis.__tegaraResponseMetadata || !globalThis.__tegaraResponseMetadata.metadata) {
      throw new Error(`${label}: the read did not pass through the patched proof-verifying query (no verified-call marker)`);
    }
    return docs;
  };
};

// every member the factory reads, named so a caller that omits one refuses HERE rather than
// building a bundle whose hook is undefined and failing later inside the writer
const REQUIRED_ENV = [
  "poolId", "contractId", "writerIdB58", "writerHex", "chainIdPin", "protocolPin", "bootstrap",
  "runEpochs", "contextFor", "sdk", "dpp", "createDocument", "keyA", "transferKey", "submitSigned",
  "waitOnly", "rehydrate", "rememberStt", "transferMetaByBytes", "verifyGateCapture", "resolvePool",
  "provedQuery", "openJournal", "readContractNonce", "readIdentityNonce", "readBalance",
  "idHex", "sha256hex",
];

/**
 * makeEpochDepsFactory(env) -> epochDepsFor(ctx, completedEpochs)
 *   -> { deps, prefetched, contractNonce, identityNonce, clearLastReservation }
 *
 * EVERY BUNDLE IS BUILT PER EPOCH from that epoch's own context, so a second epoch cannot inherit
 * the first one's row map, identifier helper, figures or prefetched nonces. The prefetch and the
 * last-reservation pointer live INSIDE one bundle for the same reason: they are consumed within
 * one epoch's steps and mean nothing outside them.
 */
const makeEpochDepsFactory = (env) => {
  if (!env || typeof env !== "object") refuse("makeEpochDepsFactory needs its environment");
  for (const k of REQUIRED_ENV) {
    if (env[k] === undefined || env[k] === null) refuse(`makeEpochDepsFactory needs env.${k}`);
  }
  if (!Array.isArray(env.runEpochs) || env.runEpochs.length === 0) {
    refuse("makeEpochDepsFactory needs the run's epochs");
  }
  const { poolId: POOL, contractId: V11, writerIdB58: ID_A, writerHex: A_HEX, chainIdPin: pin,
    protocolPin: PROTOCOL_PIN, bootstrap: BOOTSTRAP, runEpochs: RUN_EPOCHS, contextFor, sdk, dpp,
    createDocument, keyA, transferKey, submitSigned, waitOnly, rehydrate, rememberStt,
    transferMetaByBytes, verifyGateCapture, resolvePool, provedQuery, openJournal,
    readContractNonce, readIdentityNonce, readBalance, idHex, sha256hex } = env;

  return (ctx, completedEpochs) => {
    // the completed record is REQUIRED rather than defaulted: a bundle built without one would
    // answer the lifecycle question from nothing, and the writer reads that answer to choose the
    // next epoch. An absent record refuses here rather than failing later on a member of undefined.
    if (!(completedEpochs instanceof Set)) refuse("epochDepsFor needs the run's completed-epoch record; the lifecycle answer is read from it");
    if (!ctx || typeof ctx.epochIndex !== "number") refuse("epochDepsFor needs the epoch's context");

    // ---- the document layer: deterministic ids, one normalizer both ways ----
    const BYTE_FIELDS = { platformAccrual: ["poolId", "funderId"],
      transferReservation: ["poolId", "accrualId", "transitionHash"],
      transferReceipt: ["poolId", "accrualId", "transitionHash", "transitionBytes", "proofBytes",
        "metadataBytes", "blockHeight", "timeMs", "quorumHash"],
      receiptProofPart: ["poolId", "accrualId", "bytes"] };
    const TYPE_OF = { accrual: "platformAccrual", reservation: "transferReservation",
      receipt: "transferReceipt", part: "receiptProofPart" };
    const docIdOfObject = (object, key) => {
      if (object === "accrual") {
        const row = ctx.rowFor(key.accrualId);
        if (!row) throw new Error(`no entitlement row for accrual ${key.accrualId}`);
        return { b58: row.accrualIdB58, entropy: row.accrualEntropy };
      }
      const subject = object === "part" ? `${key.accrualId}#${key.partIndex}` : key.accrualId;
      const d = ctx.docIdFor(TYPE_OF[object], subject);
      return { b58: d.b58, entropy: d.entropy };
    };
    const norm = (fields) => {
      const out = {};
      for (const [k, v] of Object.entries(fields)) {
        if (k.startsWith("$")) continue;
        out[k] = (v && (v instanceof Uint8Array || Buffer.isBuffer(v))) ? Buffer.from(v).toString("hex")
          : (typeof v === "bigint" ? Number(v) : v);
      }
      return out;
    };
    const denorm = (type, fields) => {
      const out = {};
      for (const [k, v] of Object.entries(fields)) {
        out[k] = BYTE_FIELDS[type].includes(k) ? Buffer.from(v, "hex") : v;
      }
      return out;
    };
    // THE PIN CHECK IS THE DECISION AND IT LIVES HERE. The raw read is injected, so this module
    // never imports by container path and a battery can answer with any metadata it likes. A read
    // whose chain or protocol version is not the pinned one REFUSES rather than returning a nonce
    // derived from a chain this run did not pin.
    const contractNonce = async () => {
      const r = await readContractNonce();
      if (r.metadata.chainId !== pin || Number(r.metadata.protocolVersion) !== PROTOCOL_PIN) {
        throw new Error(`the proved contract-nonce read fails the pins (chain ${r.metadata.chainId}, protocol ${r.metadata.protocolVersion})`);
      }
      return r.nonce + 1n;
    };
    const identityNonce = async () => {
      const r = await readIdentityNonce();
      if (r.metadata.chainId !== pin || Number(r.metadata.protocolVersion) !== PROTOCOL_PIN) {
        throw new Error(`the proved identity-nonce read fails the pins (chain ${r.metadata.chainId}, protocol ${r.metadata.protocolVersion})`);
      }
      return r.nonce + 1n;
    };
    const mkDoc = (type, fields, id58, entropy) => {
      const doc = createDocument(new dpp.IdentifierWASM(V11), type, denorm(type, fields),
        new dpp.IdentifierWASM(ID_A), undefined, id58);
      doc.entropy = new Uint8Array(entropy);
      return doc;
    };
    // the FETCH resolves through each type's UNIQUE LOGICAL BINDING (the
    // spec's document-write recovery rule; the wider-scope pass's finding
    // 5): a conforming branch that wrote the logical row under DIFFERENT
    // entropy is still found, so recovery converges on the document rather
    // than on this driver's private id convention, which remains the
    // WRITE-side convention only
    const logicalWhere = (object, key) => {
      if (object === "accrual") {
        const row = ctx.rowFor(key.accrualId);
        if (!row) throw new Error(`no entitlement row for accrual ${key.accrualId}`);
        return [["poolId", "==", Buffer.from(POOL, "hex")],
          ["funderId", "==", Buffer.from(row.funderHex, "hex")], ["epochIndex", "==", key.epochIndex]];
      }
      if (object === "part") {
        return [["accrualId", "==", Buffer.from(key.accrualId, "hex")], ["partIndex", "==", key.partIndex]];
      }
      return [["accrualId", "==", Buffer.from(key.accrualId, "hex")]]; // reservation, receipt
    };
    const documents = {
      fetch: async (object, key) => {
        const found = await sdk.documents.query(V11, TYPE_OF[object], logicalWhere(object, key));
        if (found.length > 1) throw new Error(`the unique logical binding for ${object} returned ${found.length} documents; refusing`);
        if (found.length !== 1) return { found: false };
        const props = typeof found[0].getProperties === "function" ? found[0].getProperties() : found[0].properties;
        return { found: true, fields: norm(props) };
      },
      write: async (object, key, expected) => {
        const { b58, entropy } = docIdOfObject(object, key);
        const doc = mkDoc(TYPE_OF[object], expected, b58, entropy);
        const stt = sdk.documents.createStateTransition(doc, "create", { identityContractNonce: await contractNonce() });
        stt.sign(keyA.privateKey, keyA.publicKey);
        return submitSigned(stt);
      },
    };

    // ---- SYNCHRONOUS builders over prefetched proved nonces (the module's
    // contract fixes the builders sync; the prefetch happens per accrual just
    // before the step, and nothing else consumes those nonces in between) ----
    const prefetched = { identityNonce: null, contractNonce: null, headerContractNonce: null };
    // KEYED BY ACCRUAL, not a bare "last" (a soundness-review finding). The old single pointer was correct only
    // because the epoch loop clears it between accruals, which is an invariant maintained at a
    // distance from the thing it protects. A map makes "the id this process built FOR THIS
    // ACCRUAL" a local, checkable property. It is no longer the ANSWER, only a cross-check
    // against the ledger, so nothing depends on the clear being called at the right moment.
    const builtReservationDocIdByAccrual = new Map();
    const buildTransferTransition = ({ accrualId, amountCredits }) => {
      const row = ctx.rowFor(accrualId);
      if (prefetched.identityNonce === null) throw new Error("the identity nonce was not prefetched for this accrual");
      const nonce = prefetched.identityNonce; prefetched.identityNonce = null; // consumed once
      // THE NAMED CALLABLE, the spec's binding; userFeeIncrease stays unset
      // (zero); the E3 STAND-IN key convention signs (loudly marked in the runner)
      const stt = sdk.identities.createStateTransition("creditTransfer", {
        identityId: ID_A, amount: BigInt(amountCredits), recipientId: row.recipientB58, identityNonce: nonce });
      stt.sign(transferKey.privateKey, transferKey.publicKey);
      const transitionBytes = rememberStt(stt);
      transferMetaByBytes.set(transitionBytes, { recipientB58: row.recipientB58, amountCredits });
      return { transitionBytes, transitionHash: sha256hex(Buffer.from(transitionBytes, "hex")) };
    };
    const reservationIdFor = (transferHash) => docIdMod.reservationIdForTransfer({
      generateId: (...a) => dpp.DocumentWASM.generateId(...a), ownerId: ID_A, contractId: V11, transferHash });
    const buildReservationTransition = ({ poolId, accrualId, boundTransferHash }) => {
      if (prefetched.contractNonce === null) throw new Error("the contract nonce was not prefetched for this accrual");
      const nonce = prefetched.contractNonce; prefetched.contractNonce = null; // consumed once
      // THE IDENTIFIER IS DERIVED FROM THE BOUND TRANSFER (tegara/docs/NONCE_OWNERSHIP.md), so two
      // pools of this writer holding byte-identical transfers build the SAME reservation identifier
      // and the ledger refuses the second. Reservations built before this keep accrual-derived
      // identifiers; every reader fetches a reservation by its accrual, so both read alike.
      const { b58, hex, entropy } = reservationIdFor(boundTransferHash);
      builtReservationDocIdByAccrual.set(accrualId, hex);
      const doc = mkDoc("transferReservation",
        { poolId, accrualId, transitionHash: boundTransferHash }, b58, entropy);
      const stt = sdk.documents.createStateTransition(doc, "create", { identityContractNonce: nonce });
      stt.sign(keyA.privateKey, keyA.publicKey);
      const transitionBytes = rememberStt(stt);
      return { transitionBytes, transitionHash: sha256hex(Buffer.from(transitionBytes, "hex")) };
    };

    // ---- captures (the battery's construction) ----
    const mkCapture = async ({ kind, object, extra, rec, transitionHex, gen = 1 }) => {
      const record = {
        v: 1, kind, object, gen, poolId: POOL, epochIndex: ctx.epochIndex,
        transitionBytes: transitionHex,
        transitionHash: sha256hex(Buffer.from(transitionHex, "hex")),
        proofMsg: rec.proofMsg, metadataMsg: rec.metadataMsg,
        inclusionHeight: String(rec.metadata.height),
        heightRoute: "tenderdash-tx",
        signerIdentity: A_HEX, signerKeyId: Number(keyA.publicKey.keyId ?? 1),
        ...extra,
      };
      return captureRecord.signCapture(record, keyA.privateKey);
    };

    // ---- the composed deps ----
    const awaitByHash = async (hash) => {
      const j = openJournal(POOL);
      const rec = j.records.find((r) => r.transitionHash === hash && r.transitionBytes);
      if (!rec) return rawCapture.transportFailure("no journaled bytes for the hash; wait-only next pass");
      try { return await waitOnly(rehydrate(rec.transitionBytes, hash)); }
      catch (e) { return rawCapture.transportFailure(msgOf(e)); }
    };
    const deps = {
      verifyGateCapture,
      identities: { writer: A_HEX, income: A_HEX },
      chainIdPin: pin,
      feeCeilings: balanceCheckMod.D2_FEE_CEILINGS, // duty D2's recorded constants (the measure path), replacing the retired provisional single constant
      transferBytesBound: battery.D1_BOUNDS.transitionBytesMax,
      discoveryOpts: {},
      // discovery: ONE harness epoch, proved:false (C1 is open; income unproved)
      // DISCOVERY ANSWERS THE WHOLE RUN, not the one epoch this driver used to work. It stays
      // proved:false, because the harness income is unproved and C1 is open; what changed is the
      // EXTENT, which must cover every epoch the contexts were built for, or startRun would
      // resolve a universe the calculation and the steps disagree about.
      fetchRange: async (start, end) => ({ proved: false,
        epochs: RUN_EPOCHS.filter((n) => n >= start && n <= end).map((n) => ({ number: n })) }),
      // EVERY CALCULATION FIELD GOES TO THE WRITER, `carryInCredits` included when the
      // calculation supplies it. This still rebuilds an object rather than forwarding the
      // row whole, because the driver's own display and document-identity fields are not
      // the writer's business; what changed is that the carry member is no longer among the
      // ones dropped, and the writer's never-receives-carry refusal cannot fire on a member
      // it never sees. An epoch outside this run REFUSES inside the calculation rather than
      // answering with an empty set, which the writer would read as an epoch owing nobody.
      //
      // THE NONZERO CARRY IS REACHABLE SINCE THE F3 REFACTOR. A run of more than one epoch carries
      // into every epoch above its first, so the member is no longer omitted everywhere by
      // construction. A one-epoch run is still zero-carry by the recursion's base case, which is
      // the same behaviour as before.
      //
      // THE ROWS COME FROM THE ASKED-FOR EPOCH'S OWN CONTEXT, and an epoch outside the run refuses
      // inside the context builder rather than answering with an empty set, which the writer would
      // read as an epoch owing nobody anything.
      // THIS HOOK ANSWERS ANY EPOCH IN THE RUN, deliberately. startRun is a RUN-LEVEL consumer: it
      // walks the whole universe measuring what each epoch owes, and it holds the first epoch's
      // bundle while doing so. A first attempt at this fold refused a different epoch, which looked
      // stricter and broke that walk on the first live resume. What IS bound to one epoch is
      // everything taken from ctx below, the figures, the row lookup and the identifier helper, and
      // the claim is stated at that width rather than as exclusivity this hook does not have.
      entitlementsForEpoch: (epochIndex) => contextFor(epochIndex).rows.map((r) => ({
        accrualId: r.accrualId, amountCredits: r.amountCredits, recipientId: r.recipientId,
        ...("carryInCredits" in r ? { carryInCredits: r.carryInCredits } : {}) })),
      // THE FIGURES ARE THIS CONTEXT'S, not a single set captured for the run. The writer asks
      // this while working one epoch, and the dependency bundle it holds was built from that
      // epoch's context, so the two cannot drift apart.
      epochNumbers: () => ({ grossCredits: ctx.figures.grossCredits, feeCredits: ctx.figures.feeCredits,
        allocationHash: ctx.figures.allocationHash, memberCount: ctx.figures.memberCount,
        calcVersion: ctx.figures.calcVersion }),
      // THE LIFECYCLE ANSWER IS THIS RUN'S OWN COMPLETED RECORD, and it was a flat false. That was
      // honest while a run worked one epoch, because the writer picks the next INCOMPLETE epoch and
      // there was never a next one to pick. Over a run of more than one it is a live blocker: the
      // writer would choose the first epoch forever and never advance, which the loop's
      // epoch-agreement check catches by name rather than letting a later epoch's header be written
      // under the first one's identity.
      //
      // THE DIRECTION IS FAIL-CLOSED. An epoch is reported complete ONLY after this run finished it
      // with every positive row answered and terminal. Anything else answers false, so the writer
      // may be told there is more to do when there is not, and never the reverse.
      epochDistributionComplete: (epochIndex) => completedEpochs.has(epochIndex),
      // the PER-POOL proved resolver: the target and the canonical pool
      // answer from their proved records with real per-epoch rows (the
      // admission's store-wide obligations, including the canonical
      // specimen's wedged epoch), and probe-debris journals answer at the
      // stated journal-writer width, loudly
      resolvePool,
      fetchBalanceWithMetadata: async () => {
        const r = await readBalance();
        return { balance: String(r.balance), metadata: { chainId: r.metadata.chainId,
          protocolVersion: r.metadata.protocolVersion, height: String(r.metadata.height) } };
      },
      // the fresh header build exists in BOOTSTRAP mode only (a resume run
      // owns no header construction; the canonical journal holds it). The
      // builder is synchronous over a prefetched contract nonce, the same
      // contract as the transfer-step builders, with the deterministic
      // document identity convention
      buildHeaderTransition: ({ poolId, epochIndex, expectedContents }) => {
        if (!BOOTSTRAP) throw new Error("the resume run never builds a fresh header; the canonical journal holds it");
        if (prefetched.headerContractNonce === null) throw new Error("the header contract nonce was not prefetched");
        const nonce = prefetched.headerContractNonce; prefetched.headerContractNonce = null; // consumed once
        if (epochIndex !== ctx.epochIndex) {
          throw new Error(`the header build was asked for epoch ${epochIndex} while this context is epoch ${ctx.epochIndex}; refusing to derive a header identity under the wrong epoch`);
        }
        const d = ctx.docIdFor("epochHeader", `header#${epochIndex}`);
        const fields = { poolId: Buffer.from(poolId, "hex"), epochIndex,
          grossCredits: expectedContents.grossCredits, feeCredits: expectedContents.feeCredits,
          allocationHash: Buffer.from(expectedContents.allocationHash, "hex"),
          memberCount: expectedContents.memberCount, calcVersion: expectedContents.calcVersion };
        const doc = createDocument(new dpp.IdentifierWASM(V11), "epochHeader", fields,
          new dpp.IdentifierWASM(ID_A), undefined, d.b58);
        doc.entropy = new Uint8Array(d.entropy);
        const stt = sdk.documents.createStateTransition(doc, "create", { identityContractNonce: nonce });
        stt.sign(keyA.privateKey, keyA.publicKey);
        const transitionBytes = rememberStt(stt);
        return { transitionBytes, transitionHash: sha256hex(Buffer.from(transitionBytes, "hex")),
          expectedDocumentId: d.hex };
      },
      buildHeaderCapture: ({ writeAhead, expectedContents, result }) =>
        mkCapture({ kind: captureRecord.HEADER_KIND, object: "header",
          extra: { contractId: idHex(V11), expectedDocumentId: writeAhead.expectedDocumentId, expectedContents },
          rec: result, transitionHex: writeAhead.transitionBytes }),
      // THE DUPLICATE-HEADER RECOVERY'S READ, through the one proved query (a soundness-review finding). It
      // used to be a bare `sdk.documents.query`, so an ordinary endpoint answer with
      // matching fields could authorize the degraded continuation while the journal recorded
      // it under the proved route. Three things changed and each is load-bearing.
      //
      // THE MARKER CHECK IS NOT OPTIONAL: `provedQuery` throws when the patched
      // proof-verifying wrapper did not run, so an unproved read cannot reach the writer at
      // all rather than reaching it unlabelled.
      //
      // THE ANSWER ATTESTS, and only after that check. The writer refuses an answer that
      // does not, so an adapter that stops proving stops being believed instead of being
      // trusted by default.
      //
      // THE RETURNED DOCUMENT IS CHECKED AGAINST THE KEY THAT WAS ASKED FOR. A response for
      // a different pool or epoch is refused here rather than left for the writer's field
      // comparison, because an adapter that answers about the wrong subject has not answered
      // the question at all.
      provedHeaderQuery: async (poolId, epochIndex) => {
        const label = `provedHeaderQuery(${poolId.slice(0, 12)}..., epoch ${epochIndex})`;
        const found = await provedQuery("epochHeader",
          [["poolId", "==", Buffer.from(poolId, "hex")], ["epochIndex", "==", epochIndex]], label);
        // a VERIFIED ABSENCE, which is a different thing from an unverified one: the marker
        // check above already established that this answer came through the proving wrapper
        if (found.length === 0) return { found: false, proved: true };
        if (found.length !== 1) {
          throw new Error(`${label}: the proved read served ${found.length} headers for one pool and epoch; refusing rather than choosing one`);
        }
        const props = typeof found[0].getProperties === "function" ? found[0].getProperties() : found[0].properties;
        const fields = norm(props);
        if (fields.poolId !== poolId || fields.epochIndex !== epochIndex) {
          throw new Error(`${label}: the proved read served a header for pool ${String(fields.poolId).slice(0, 12)}... epoch ${fields.epochIndex}, which is not what was asked for; refusing`);
        }
        return { found: true, proved: true, documentId: idHex(found[0].id), fields };
      },
      broadcastAndAwait: async (hash, bytesHex) => {
        try { return await submitSigned(rehydrate(bytesHex, hash)); }
        catch (e) { return rawCapture.transportFailure(msgOf(e)); }
      },
      awaitResult: awaitByHash,
      documents,
      accrualPayload: (epochIndex, row) => {
        const r = ctx.rowFor(row.accrualId);
        return { poolId: POOL, funderId: r.funderHex, epochIndex,
          amountCredits: Number(r.amountCredits), shareBps: r.bps };
      },
      buildTransferTransition,
      buildReservationTransition,
      // THE RESERVATION DOCUMENT'S IDENTIFIER COMES FROM THE LEDGER (a soundness-review finding), never from state
      // this process happens to hold. The old version returned a variable set at BUILD time, so
      // the wait-only resume route, which by design builds nothing, found it empty and threw
      // `no reservation was built in this step`. A run interrupted between the reservation's
      // sent marker and its success record could therefore never be resumed: every resume ended
      // with an unhandled error instead of a status, and the pool was stuck for good. Found by
      // the first live payment run, 2026-09-22.
      //
      // WHY DERIVING IT WOULD NOT HAVE BEEN A FIX. `docIdOfObject` is deterministic, so the
      // builder's id is recomputable from the accrual alone and that looks like the cheap
      // repair. It answers which id THIS writer WOULD have used, which is a different question
      // from which document is there. On a resume the bytes being waited on were produced by an
      // earlier process, and the runner's own header (`e2DistributeRun.mjs`) discusses a
      // conforming branch writing a logical row under different entropy, so the recomputed id
      // and the real one can differ. A derivation cannot tell those cases apart.
      //
      // WHAT MAKES THE LOOKUP CORRECT is the CONTRACT, not the document-write recovery rule.
      // An earlier version of this comment cited that rule, and a review was right that it does
      // not apply: the spec scopes it to accruals, proof parts and the receipt, and reservations
      // have their own success and holder rules. The reservation's guarantee is narrower and
      // sufficient. `contractV11.cjs` makes `transferReservation` unique by accrual, immutable
      // and undeletable, so once THIS transition has genuinely succeeded no later branch can
      // put a different document under this accrual. The row served under the unique binding is
      // therefore the one the record is about. A branch that LOST the unique index never reaches
      // here: a duplicate refusal is not a success, and it enters the refusal and foreign-claim
      // arms below instead.
      //
      // IT REPORTS RATHER THAN THROWS. Every unanswerable case is an answer the caller turns
      // into a named non-terminal status, because a read that cannot be completed must leave a
      // re-run able to recover rather than end the run unhandled. That was the other half of
      // a soundness-review finding, and the first version of this repair still left two ways to throw, a rejecting
      // query and a served identifier that cannot be decoded, both of which a review executed.
      //
      // WHAT "RECOVERABLE" DOES AND DOES NOT PROMISE. A later pass resumes IF the read becomes
      // answerable AND this accrual's transfer nonce has not been consumed in the meantime by a
      // row the loop went on to work. A review reproduced that sequence: the accrual returns
      // pending, a later row sends under the nonce this one had built against, and the resumed
      // transfer is refused. That is the spec's already-recorded nonce-stranding limitation
      // reached by a new route, not a new one, and the wording here no longer says otherwise.
      // A persistent multiplicity or a persistent disagreement is also not something waiting
      // fixes; both are conditions for an operator, and the status is deliberately conservative
      // rather than terminal because neither establishes an execution refusal.
      //
      // WIDTH, STATED: this read is the plain document query, not the proof-verifying one, so it
      // carries the same trust as `fetchReservation` and `observeReceipt` beside it, which the
      // foreign-claim decision below already rests on. Moving all three to the proved route is a
      // separate change and is not made here.
      // THE ARGUMENT IS DEFAULTED because a call with none must produce a REFUSAL, not a
      // destructuring crash. The whole point of this repair is that an unanswerable identifier
      // stops one accrual with a named condition rather than ending the run, and a throw here
      // would put the old failure back under a new message.
      // THE ARGUMENT IS NORMALIZED rather than destructured, because `null` is not `undefined`
      // and a default parameter does not cover it: `({ x } = {})` still throws on an explicit
      // null. A review found that hole.
      // a soundness-review finding: WHETHER A PERSISTED TRANSITION CAN STILL EXECUTE, from the nonce inside its own bytes
      // and the signer's RAW stored nonce on the proved route, under the same pin check as the nonce
      // reads above, decided by e2NonceWindow.cjs. Any read or decode that fails THROWS, and the
      // writer then claims nothing about the bytes. The transfer's signer is read as the writer
      // identity, which is the income identity in the bootstrap shape this runner serves.
      transitionNonceState: async (object, bytesHex) => {
        if (!["header", "reservation", "transfer"].includes(object)) throw new Error(`no nonce rule for ${object}`);
        const stt = dpp.StateTransitionWASM.fromBytes(Buffer.from(bytesHex, "hex"));
        const transitionNonce = object === "transfer"
          ? BigInt(dpp.IdentityCreditTransferWASM.fromStateTransition(stt).nonce)
          : BigInt(stt.getIdentityContractNonce());
        const r = object === "transfer" ? await readIdentityNonce() : await readContractNonce();
        if (r.metadata.chainId !== pin || Number(r.metadata.protocolVersion) !== PROTOCOL_PIN) {
          throw new Error(`the proved nonce read fails the pins (chain ${r.metadata.chainId}, protocol ${r.metadata.protocolVersion})`);
        }
        if (typeof r.raw !== "bigint") throw new Error("the proved nonce read carries no raw stored value, so a nonce below the tip cannot be classified");
        return { ...nonceUsability({ transitionNonce, rawExisting: r.raw }), transitionNonce,
          observedHeight: String(r.metadata.height) };
      },
      // a soundness-review finding: the PROVED absence of any reservation for an accrual, the ledger's half of the evidence
      // that a reservation whose bytes can never execute never executed either. A read that fails
      // throws, so the writer never rebuilds on an unperformed check.
      provedReservationAbsent: async (accrualId) => {
        if (typeof accrualId !== "string" || !/^[0-9a-f]{64}$/.test(accrualId)) throw new Error("the accrual identifier is missing or malformed");
        const found = await provedQuery("transferReservation", [["accrualId", "==", Buffer.from(accrualId, "hex")]],
          `provedReservationAbsent(${accrualId.slice(0, 12)}...)`);
        if (!Array.isArray(found)) throw new Error("the proved reservation read answered something that is not a list");
        return { absent: found.length === 0, count: found.length };
      },
      reservationDocumentIdOf: async (key) => {
        const accrualId = (key && typeof key === "object") ? key.accrualId : undefined;
        if (typeof accrualId !== "string" || !/^[0-9a-f]{64}$/.test(accrualId)) {
          return { found: false, reason: "the accrual identifier is missing or malformed" };
        }
        // THE QUERY ITSELF CAN REJECT, and an uncaught rejection here is the original defect
        // wearing a different coat: the run would end unhandled on a transport failure instead
        // of stopping one accrual recoverably.
        let found;
        try {
          found = await sdk.documents.query(V11, "transferReservation",
            [["accrualId", "==", Buffer.from(accrualId, "hex")]]);
        } catch (e) {
          return { found: false, reason: `the reservation read did not complete (${(e && e.message) || e})` };
        }
        if (!Array.isArray(found)) {
          return { found: false, reason: "the reservation read answered something that is not a list of documents" };
        }
        if (found.length === 0) {
          return { found: false, reason: "the ledger serves no reservation for this accrual" };
        }
        if (found.length !== 1) {
          return { found: false, reason: `the ledger serves ${found.length} reservations for this accrual, which the unique binding forbids` };
        }
        // AND THE SERVED IDENTIFIER MAY NOT DECODE. Same reasoning as the query above.
        let ledgerId;
        try { ledgerId = idHex(found[0].id); }
        catch (e) { return { found: false, reason: `the served reservation's identifier could not be read (${(e && e.message) || e})` }; }
        if (typeof ledgerId !== "string" || !/^[0-9a-f]{64}$/.test(ledgerId)) {
          return { found: false, reason: "the served reservation's identifier is not a 32-byte value, which the record requires" };
        }
        const builtHere = builtReservationDocIdByAccrual.get(accrualId);
        // A CROSS-CHECK ON A STATE THAT SHOULD BE UNREACHABLE. When this process built the
        // reservation AND its transition succeeded, the document under this accrual's unique
        // binding is that one, so the two must agree. They are compared anyway, because the
        // alternative to comparing is assuming, and a disagreement would mean the success
        // belonged to a different document than the record is about to name.
        if (builtHere && builtHere !== ledgerId) {
          return { found: false,
            reason: `the reservation built here is ${builtHere.slice(0, 12)} and the ledger serves ${ledgerId.slice(0, 12)} for the same accrual` };
        }
        return { found: true, documentId: ledgerId };
      },
      fetchReservation: async (poolId, epochIndex, accrualId) => {
        const found = await sdk.documents.query(V11, "transferReservation",
          [["accrualId", "==", Buffer.from(accrualId, "hex")]]);
        if (found.length !== 1) return { found: false };
        const props = typeof found[0].getProperties === "function" ? found[0].getProperties() : found[0].properties;
        return { found: true, boundTransferHash: Buffer.from(props.transitionHash).toString("hex") };
      },
      observeReceipt: async (poolId, epochIndex, accrualId, transferHash) => {
        const found = await sdk.documents.query(V11, "transferReceipt",
          [["transitionHash", "==", Buffer.from(transferHash, "hex")]]);
        if (found.length !== 1) return { found: false };
        return { found: true, documentId: idHex(found[0].id) };
      },
      // the capture carries its transfer's GENERATION, which a replacement makes greater than 1
      buildReceiptCapture: ({ accrualId, writeAhead, result }) =>
        mkCapture({ kind: captureRecord.RECEIPT_KIND, object: "transfer", gen: writeAhead.gen || 1,
          extra: { accrualId }, rec: result, transitionHex: writeAhead.transitionBytes }),
      // WHO ELSE CLAIMS THESE TRANSFER BYTES, on the proved route (tegara/docs/NONCE_OWNERSHIP.md).
      // Two claims can exist, each unique on the ledger: the reservation at the identifier derived
      // from the bytes, and a receipt for their hash. A LEGACY reservation of another accrual is not
      // findable here, since reservations have no transfer-hash index, and the result says nothing
      // about one. Any read that fails throws, so a caller never takes an unperformed check as
      // "unclaimed". A served document that does not bind these bytes is refused as inconsistent.
      transferClaims: async (transferHash) => {
        if (typeof transferHash !== "string" || !/^[0-9a-f]{64}$/.test(transferHash)) throw new Error("the transfer hash is missing or malformed");
        const rid = reservationIdFor(transferHash);
        const label = `transferClaims(${transferHash.slice(0, 12)}...)`;
        const reservations = await provedQuery("transferReservation", [["$id", "==", rid.b58]], label);
        const receipts = await provedQuery("transferReceipt", [["transitionHash", "==", Buffer.from(transferHash, "hex")]], label);
        if (!Array.isArray(reservations) || !Array.isArray(receipts)) throw new Error(`${label}: a proved read answered something that is not a list`);
        const claimsOf = (kind, docs) => docs.map((d) => {
          const f = norm(typeof d.getProperties === "function" ? d.getProperties() : d.properties);
          if (f.transitionHash !== transferHash) throw new Error(`${label}: a served ${kind} does not bind these bytes`);
          return { kind, accrualId: f.accrualId, poolId: f.poolId, documentId: idHex(d.id) };
        });
        return { reservationId: rid.hex,
          claims: [...claimsOf("reservation-by-transfer", reservations), ...claimsOf("receipt-by-transition", receipts)] };
      },
      receiptPayloads: (epochIndex, accrualId) => {
        const j = openJournal(POOL);
        const cap = j.records.find((r) => r.kind === captureRecord.RECEIPT_KIND
          && r.epochIndex === epochIndex && r.accrualId === accrualId);
        if (!cap) throw new Error("receiptPayloads: no journaled capture for the accrual");
        const split = battery.splitCarrier(cap.proofMsg);
        const md = rawCapture.decodeMetadata(cap.metadataMsg);
        const proof = rawCapture.decodeProofCarrier(cap.proofMsg);
        const be8 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b.toString("hex"); };
        const receipt = { poolId: POOL, accrualId, transitionHash: cap.transitionHash,
          transitionBytes: cap.transitionBytes, proofBytes: split.proofBytes,
          proofPartCount: split.proofPartCount, metadataBytes: cap.metadataMsg,
          blockHeight: be8(md.height), coreChainLockedHeight: Number(md.coreChainLockedHeight),
          timeMs: be8(md.timeMs), quorumHash: proof.quorumHashHex, round: Number(proof.round) };
        const parts = split.parts.map((p) => ({ poolId: POOL, accrualId, partIndex: p.partIndex, bytes: p.bytes }));
        return { parts, receipt };
      },
    };
    return { deps, prefetched, contractNonce, identityNonce,
      // KEPT so the epoch loop's per-accrual call still means something, but it no longer
      // guards a correct answer: the id comes from the ledger keyed by the accrual, so a stale
      // entry cannot be returned for a different accrual whether or not this is called.
      clearLastReservation: () => { builtReservationDocIdByAccrual.clear(); } };
  };
};

module.exports = { makeEpochDepsFactory, makeProvedQuery, REQUIRED_ENV };
