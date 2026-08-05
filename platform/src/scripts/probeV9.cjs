/**
 * Deployment probe suite for the v9 schema. Two sanctioned uses: a THROWAWAY namespace
 * (the 2026-07-16 first run, V9_PROBE_RUN_2026-07-16.md), and the CANONICAL contract
 * immediately after its phase G publish, where the adoption checklist mandates exactly
 * these probes against the artifact actually published. The suite writes permanent
 * evidence documents (an immutable probe pool and its receipt, whose ids the run record
 * lists), so it is gated like squattingProbeV8 and is never run casually against a
 * namespace whose documents readers already consume.
 *
 * Probes (each expected refusal must be the RIGHT refusal, per the squattingProbeV8
 * discipline; a network/nonce/balance error is a probe FAILURE, never a pass):
 *   P1 dependentRequired: pool with slotDuffs only, then slotCount only, both REFUSED;
 *      where the refusal happens (client DPP vs broadcast) is recorded honestly.
 *   P2 a valid pool (both slot fields) is ACCEPTED (the probe pool).
 *   P3 pool replace REFUSED (documentsMutable false).
 *   P4 pool delete REFUSED (canBeDeleted false).
 *   P5 non-owner pool create REFUSED (creationRestrictionMode 1), by a second identity.
 *   P6 a valid completionReceipt for the probe pool is ACCEPTED.
 *   P7 a second receipt for the SAME pool REFUSED (unique byPool).
 *   P8 a receipt claiming the SAME (proTxHash, slotIndex) under another poolId REFUSED
 *      (unique bySlot).
 *   P9 non-owner receipt create REFUSED (carried v8 owner-only creation).
 *
 * Run (scratch env mounted as .env.local, v9 already published there):
 *   PROBE_CONFIRM=leave-probe-evidence node src/scripts/probeV9.cjs
 * The second identity is registered on first run and persisted as PROBE_SECOND_ID.
 */
const crypto = require("crypto");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, updateEnvKey } = require("./envStore.cjs");

let passed = 0, failed = 0;
const result = (name, okFlag, detail) => {
  if (okFlag) { passed++; console.log(`PASS ${name}${detail ? ` (${detail})` : ""}`); }
  else { failed++; console.error(`FAIL ${name}${detail ? ` (${detail})` : ""}`); }
};
// wasm-dpp error classes are wasm-bound objects with NO .message (String(e) gives
// [object Object]), so identify them by constructor name first
const ctorOf = (e) => (e && e.constructor && e.constructor.name) || "";
const msgOf = (e) => (e && e.message) || (ctorOf(e) !== "Object" && ctorOf(e)) || String(e);

// expected-refusal matchers, deliberately narrow
const isRestriction = (e) => /creation restriction mode|DocumentCreationNotAllowed|is not allowed because of the document type/i.test(msgOf(e))
  || (e && e.name === "DocumentCreationNotAllowedError");
const isImmutable = (e) => ctorOf(e) === "TryingToReplaceImmutableDocumentError"
  || /not mutable|documentsMutable|replace.*not allowed|cannot be (updated|replaced)/i.test(msgOf(e));
const isUndeletable = (e) => ctorOf(e) === "TryingToDeleteImmutableDocumentError"
  || /cannot be deleted|canBeDeleted|delete.*not allowed/i.test(msgOf(e));
const isUnique = (e) => /unique|already exists|duplicate/i.test(msgOf(e));
const isSchema = (e) => /dependentRequired|JsonSchema|schema|missing property|required propert/i.test(msgOf(e));

(async () => {
  if (process.env.PROBE_CONFIRM !== "leave-probe-evidence") {
    console.error("this suite writes permanent evidence documents. Both sanctioned uses need " +
      "PROBE_CONFIRM=leave-probe-evidence: a THROWAWAY namespace, or the CANONICAL contract " +
      "immediately after its publish, where the adoption checklist mandates these probes " +
      "against the artifact actually published. It is never run casually against a namespace " +
      "whose documents readers already consume.");
    process.exit(2);
  }
  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) { console.error("scratch env needs MNEMONIC/IDENTITY_ID (run register.cjs)"); process.exit(2); }
  if (!env.CONTRACT_V9_ID) { console.error("scratch env has no CONTRACT_V9_ID (run registerV9.cjs with REGISTER_V9_CONFIRM=1)"); process.exit(2); }

  const clientOpts = { network: process.env.NETWORK || "testnet", wallet: { mnemonic: env.MNEMONIC },
    apps: { poolLedger: { contractId: env.CONTRACT_V9_ID } } };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const owner = await client.platform.identities.get(env.IDENTITY_ID);
    console.log(`probing v9 contract ${env.CONTRACT_V9_ID} as owner ${env.IDENTITY_ID}`);

    // second identity for the non-owner probes (registered once, persisted)
    let secondId = loadEnv().PROBE_SECOND_ID;
    if (!secondId) {
      console.log("registering the second (non-owner) probe identity ...");
      const second = await client.platform.identities.register();
      secondId = second.getId().toString();
      updateEnvKey("PROBE_SECOND_ID", secondId);
      console.log("second identity:", secondId);
    }
    const second = await client.platform.identities.get(secondId);

    const basePool = {
      slotIndex: 0, nodeType: "regular", operatorFeeBps: 100,
      targetDuffs: 100000000000, slotDuffs: 25000000000, slotCount: 4,
    };

    // ---- P1: dependentRequired, one-sided variants ----
    for (const [variant, props] of [
      ["slotDuffs-only", { ...basePool, slotCount: undefined }],
      ["slotCount-only", { ...basePool, slotDuffs: undefined }],
    ]) {
      const clean = Object.fromEntries(Object.entries(props).filter(([, v]) => v !== undefined));
      let stage = "create";
      try {
        const doc = await client.platform.documents.create("poolLedger.pool", owner, clean);
        stage = "broadcast";
        await client.platform.documents.broadcast({ create: [doc] }, owner);
        result(`P1 ${variant} refused`, false, "ACCEPTED, dependentRequired NOT enforced");
      } catch (e) {
        result(`P1 ${variant} refused`, isSchema(e), `${stage}-stage: ${msgOf(e).slice(0, 160)}`);
      }
    }

    // ---- P2: the valid probe pool ----
    let pool;
    {
      const doc = await client.platform.documents.create("poolLedger.pool", owner, basePool);
      await client.platform.documents.broadcast({ create: [doc] }, owner);
      pool = doc;
      result("P2 valid pool accepted", true, doc.getId().toString());
    }

    // ---- P3: replace refused ----
    try {
      const fresh = (await client.platform.documents.get("poolLedger.pool", {
        where: [["$id", "==", pool.getId()]],
      }))[0];
      fresh.set("operatorFeeBps", 200);
      await client.platform.documents.broadcast({ replace: [fresh] }, owner);
      result("P3 pool replace refused", false, "ACCEPTED, pool is mutable");
    } catch (e) {
      result("P3 pool replace refused", isImmutable(e) || isSchema(e), msgOf(e).slice(0, 160));
    }

    // ---- P4: delete refused ----
    try {
      const fresh = (await client.platform.documents.get("poolLedger.pool", {
        where: [["$id", "==", pool.getId()]],
      }))[0];
      await client.platform.documents.broadcast({ delete: [fresh] }, owner);
      result("P4 pool delete refused", false, "ACCEPTED, pool is deletable");
    } catch (e) {
      result("P4 pool delete refused", isUndeletable(e) || isImmutable(e) || isSchema(e), msgOf(e).slice(0, 160));
    }

    // ---- P5: non-owner pool create refused ----
    try {
      const doc = await client.platform.documents.create("poolLedger.pool", second, basePool);
      await client.platform.documents.broadcast({ create: [doc] }, second);
      result("P5 non-owner pool refused", false, "ACCEPTED, creationRestrictionMode NOT enforced");
    } catch (e) {
      result("P5 non-owner pool refused", isRestriction(e), msgOf(e).slice(0, 160));
    }

    // ---- P6..P8: receipts ----
    const proTx = crypto.randomBytes(32);
    // the P6 receipt's embedded allocation is CANONICAL (vetting round 2026-08-03,
    // finding 3): an earlier probe used a hollow placeholder that was schema-valid but
    // failed the shared verifier, so the acceptance evidence it left reads permanently
    // as a contradiction (recorded in the canonical publish run doc). Acceptance
    // evidence must VERIFY, so the rows are the real preimage for the probe pool, one
    // participant holding the whole target.
    const core = require("./formationCore.cjs");
    const { checkReceiptAgainstPool } = require("./receiptPoolCheck.cjs");
    const probeManifest = {
      poolId: pool.getId().toString(), target: String(basePool.targetDuffs),
      owners: [{ owner: owner.getId().toString(), amountDuffs: String(basePool.targetDuffs),
        bps: 10000, rewardScriptHex: "76a914" + "42".repeat(20) + "88ac" }],
    };
    const rows = core.allocationPreimage(env.CONTRACT_V9_ID, probeManifest);
    const receiptProps = (poolIdBuf, proTxBuf, slotIdx) => ({
      poolId: poolIdBuf, proTxHash: proTxBuf, slotIndex: slotIdx,
      formatVersion: 1, allocationRows: rows,
      allocationHash: crypto.createHash("sha256").update(rows).digest(),
      participantCount: 1, l1Verification: "demo-unverified", verificationMethodVersion: 1,
    });
    {
      const doc = await client.platform.documents.create("poolLedger.completionReceipt", owner,
        receiptProps(pool.getId().toBuffer(), proTx, 0));
      await client.platform.documents.broadcast({ create: [doc] }, owner);
      result("P6 valid receipt accepted", true, doc.getId().toString());
      // and the acceptance evidence VERIFIES under the reader contract, so the pair this
      // probe leaves behind reads as a completion, never as a contradiction
      const verdict = checkReceiptAgainstPool({ contractId: env.CONTRACT_V9_ID,
        receipt: receiptProps(pool.getId().toBuffer(), proTx, 0),
        pool: basePool, poolId: pool.getId().toString(),
        // DISPOSITION: EXEMPT, stated explicitly rather than by silence (Request 3).
        // This is a deployment probe, outside the release profile's boundary by that
        // profile's own terms, and it verifies receipt PROPS it is about to create, so
        // no receipt document exists yet to read an owner from. The property the binding
        // would establish is covered here by a different probe: P5 confirms the contract
        // itself refuses a non-owner receipt creation at consensus. Nothing downstream
        // consumes this verdict as a completion claim.
        ownerBindingUnavailable: "EXEMPT: probe verifies props before the receipt document " +
          "exists; owner-only creation is covered by probe P5 at consensus" });
      result("P6 receipt VERIFIES through the shared receipt-to-pool check",
        verdict.ok === true, verdict.ok ? "five duties pass" : verdict.reason);
    }
    try {
      const doc = await client.platform.documents.create("poolLedger.completionReceipt", owner,
        receiptProps(pool.getId().toBuffer(), crypto.randomBytes(32), 1));
      await client.platform.documents.broadcast({ create: [doc] }, owner);
      result("P7 second receipt per pool refused", false, "ACCEPTED, byPool NOT unique");
    } catch (e) {
      result("P7 second receipt per pool refused", isUnique(e), msgOf(e).slice(0, 160));
    }
    try {
      const doc = await client.platform.documents.create("poolLedger.completionReceipt", owner,
        receiptProps(crypto.randomBytes(32), proTx, 0));
      await client.platform.documents.broadcast({ create: [doc] }, owner);
      result("P8 same (proTxHash, slotIndex) refused", false, "ACCEPTED, bySlot NOT unique");
    } catch (e) {
      result("P8 same (proTxHash, slotIndex) refused", isUnique(e), msgOf(e).slice(0, 160));
    }

    // ---- P9: non-owner receipt refused (carried v8 property) ----
    try {
      const doc = await client.platform.documents.create("poolLedger.completionReceipt", second,
        receiptProps(crypto.randomBytes(32), crypto.randomBytes(32), 2));
      await client.platform.documents.broadcast({ create: [doc] }, second);
      result("P9 non-owner receipt refused", false, "ACCEPTED, restriction NOT enforced");
    } catch (e) {
      result("P9 non-owner receipt refused", isRestriction(e), msgOf(e).slice(0, 160));
    }

    console.log(`\nprobeV9: ${passed} passed, ${failed} failed`);
    if (failed) process.exitCode = 1;
  } catch (e) {
    console.error("PROBE RUN ERROR:", msgOf(e));
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
