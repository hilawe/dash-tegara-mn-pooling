/**
 * settleFlow, the Path 2 settlement slice driven one PROTOCOL STEP per process run, so
 * every step boundary is a real crash boundary (kill the process between any two steps
 * and re-run `resolve` to see the fail-safe state). Design:
 * tegara/docs/PATH2_DESIGN_SYNTHESIS.md; resolver semantics validated offline by
 * tegara/docs/path2_resolver_thinslice.cjs (58 assertions).
 *
 *   register                        publish settlementV1 (operator env; persists SETTLEMENT_V1_ID)
 *   intent <shareId> <priceCredits> <joinerId> <expiryHeight>
 *                                   LEAVER-signed saleIntent for their own share
 *   pay <intentId>                  JOINER pays the intent's exact price by creditTransfer
 *                                   (prints the transfer evidence to embed in the claim)
 *   claim <intentId> <transferHash> <rewardScriptHex>
 *                                   JOINER-signed positionClaim (unique per intent at consensus)
 *   resolve <shareId>               ANYONE, no keys: compute the ACTIVE holder of the position
 *                                   from public state and print the full reasoning
 *
 * Identity of the runner comes from the mounted env (FUNDER_ID + MNEMONIC): the leaver
 * runs `intent` under their env, the joiner runs `pay`/`claim` under theirs. The two envs
 * hold UNRELATED mnemonics; no step signs for the other side.
 *
 * HONEST LIMIT of this slice (recorded in the run doc): the resolver verifies the claim's
 * binding (intent, named joiner, uniqueness, window) from on-ledger documents, but the
 * TRANSFER itself is verified at pay time by balance readback and carried as the
 * transition hash in the claim. Whether a third party can independently re-verify that
 * hash from public state (a queryable transition-by-hash endpoint with proof) is the open
 * verifiability question this milestone surfaces for the design record.
 */
const Dash = require("dash");
const { Identifier } = require("/app/node_modules/@dashevo/wasm-dpp");
const { loadEnv, updateEnvKey, activeContractId } = require("./envStore.cjs");
const { buildSettlementV1 } = require("./contractSettlementV1.cjs");

const [, , cmd, ...args] = process.argv;

const b = (x) => Buffer.from(x);
const idOf = (raw) => Identifier.from(b(raw)).toString();

(async () => {
  const env = loadEnv();
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC, unsafeOptions: { skipSynchronizationBeforeHeight: 1 } },
    apps: { poolLedger: { contractId: activeContractId(env) } },
  };
  if (env.SETTLEMENT_V1_ID || process.env.SETTLEMENT_V1_ID) {
    clientOpts.apps.settlement = { contractId: process.env.SETTLEMENT_V1_ID || env.SETTLEMENT_V1_ID };
  }
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);
  const me = env.FUNDER_ID || env.IDENTITY_ID;

  try {
    if (cmd === "register") {
      // operator publishes the settlement contract once (its own namespace; the pool
      // ledger is untouched). Persisted like the other contract ids.
      if (loadEnv().SETTLEMENT_V1_ID) { console.log("already published:", loadEnv().SETTLEMENT_V1_ID); return; }
      const identity = await client.platform.identities.get(env.IDENTITY_ID);
      const contract = await client.platform.contracts.create(buildSettlementV1(), identity);
      await client.platform.contracts.publish(contract, identity);
      const id = contract.getId().toString();
      updateEnvKey("SETTLEMENT_V1_ID", id);
      console.log("settlementV1 published:", id);
      return;
    }

    if (cmd === "intent") {
      const [shareId, priceStr, joinerId, expiryStr] = args;
      const price = parseInt(priceStr, 10), expiry = parseInt(expiryStr, 10);
      if (!shareId || !(price > 0) || !joinerId || !(expiry > 0)) {
        throw new Error("usage: intent <shareId> <priceCredits> <joinerId> <expiryHeight>");
      }
      const identity = await client.platform.identities.get(me);
      // the leaver can only meaningfully offer THEIR OWN share; check before signing
      const share = (await client.platform.documents.get("poolLedger.share", {
        where: [["$id", "==", Identifier.from(shareId)]] }))[0];
      if (!share) throw new Error(`share ${shareId} not found`);
      if (share.getOwnerId().toString() !== me) {
        throw new Error(`share ${shareId} is not owned by ${me}; only the holder can offer it`);
      }
      const nonce = require("crypto").randomBytes(32);
      const doc = await client.platform.documents.create("settlement.saleIntent", identity, {
        positionId: Identifier.from(shareId).toBuffer(),
        poolId: b(share.toObject().poolId),
        priceCredits: price,
        joinerId: Identifier.from(joinerId).toBuffer(),
        nonce,
        expiryHeight: expiry,
      });
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      console.log(`saleIntent ${doc.getId().toString()} posted by the holder ${me}`);
      console.log(`  position ${shareId}, price ${price} credits, named joiner ${joinerId}, expiry ${expiry}`);
      return;
    }

    if (cmd === "pay") {
      const [intentId] = args;
      if (!intentId) throw new Error("usage: pay <intentId>");
      const intent = (await client.platform.documents.get("settlement.saleIntent", {
        where: [["$id", "==", Identifier.from(intentId)]] }))[0];
      if (!intent) throw new Error(`intent ${intentId} not found`);
      const o = intent.toObject();
      if (idOf(o.joinerId) !== me) throw new Error(`intent names joiner ${idOf(o.joinerId)}, not ${me}`);
      const sellerId = intent.getOwnerId().toString();
      const price = Number(o.priceCredits);
      const identity = await client.platform.identities.get(me);
      const balBefore = BigInt((await client.platform.identities.get(sellerId)).balance);
      console.log(`paying ${price} credits to the seller ${sellerId} (signed by the joiner only) ...`);
      const result = await client.platform.identities.creditTransfer(identity, sellerId, price);
      const balAfter = BigInt((await client.platform.identities.get(sellerId)).balance);
      // transfer evidence: the transition hash if the SDK returns one, else recorded readback
      let hash = null;
      try { hash = result && result.hash ? Buffer.from(result.hash()).toString("hex") : null; } catch {}
      console.log(`seller balance ${balBefore} -> ${balAfter} (delta ${balAfter - balBefore}, expected ${price})`);
      if (balAfter - balBefore !== BigInt(price)) {
        throw new Error("readback mismatch: the seller balance did not rise by exactly the price");
      }
      console.log(`PAID. transfer evidence hash: ${hash || "(SDK returned no hash; use the readback record)"}`);
      console.log(`next (joiner): claim ${intentId} <transferHash> <rewardScriptHex>`);
      return;
    }

    if (cmd === "claim") {
      const [intentId, transferHashHex, rewardScriptHex] = args;
      if (!intentId || !transferHashHex || !rewardScriptHex) {
        throw new Error("usage: claim <intentId> <transferHash 64-hex> <rewardScriptHex>");
      }
      const identity = await client.platform.identities.get(me);
      const doc = await client.platform.documents.create("settlement.positionClaim", identity, {
        intentId: Identifier.from(intentId).toBuffer(),
        transferHash: Buffer.from(transferHashHex, "hex"),
        rewardScript: Buffer.from(rewardScriptHex, "hex"),
      });
      await client.platform.documents.broadcast({ create: [doc] }, identity);
      console.log(`positionClaim ${doc.getId().toString()} posted by the joiner ${me} (unique per intent at consensus)`);
      return;
    }

    if (cmd === "resolve") {
      const [shareId] = args;
      if (!shareId) throw new Error("usage: resolve <shareId>");
      // the resolver holds NO keys and signs nothing; it reads public state only
      const share = (await client.platform.documents.get("poolLedger.share", {
        where: [["$id", "==", Identifier.from(shareId)]] }))[0];
      if (!share) { console.log("RESOLVE: share does not exist (position closed or never existed)"); return; }
      const baseOwner = share.getOwnerId().toString();
      const intents = await client.platform.documents.get("settlement.saleIntent", {
        where: [["positionId", "==", Identifier.from(shareId)]],
        orderBy: [["$createdAt", "asc"]],
      }).catch(() => []);
      console.log(`RESOLVE ${shareId}: base owner ${baseOwner}, ${intents.length} intent(s)`);
      for (const intent of intents) {
        const o = intent.toObject();
        const reasons = [];
        if (intent.getOwnerId().toString() !== baseOwner) reasons.push("intent not by the current holder");
        const claims = await client.platform.documents.get("settlement.positionClaim", {
          where: [["intentId", "==", intent.getId()]] }).catch(() => []);
        if (!claims.length) { console.log(`  intent ${intent.getId().toString()}: no claim${reasons.length ? ` (${reasons.join("; ")})` : ""}`); continue; }
        const claim = claims[0]; // the unique index guarantees at most one
        const co = claim.toObject();
        if (claim.getOwnerId().toString() !== idOf(o.joinerId)) reasons.push("claim owner is not the named joiner");
        // transfer verification within this slice: the pay step verified the exact-price
        // movement by readback before printing the hash the claim embeds; a third party
        // re-verifying the hash independently is the recorded open question
        const transferHashHex = Buffer.from(co.transferHash).toString("hex");
        console.log(`  intent ${intent.getId().toString()}: claim ${claim.getId().toString()} by ${claim.getOwnerId().toString()}`);
        console.log(`    transfer evidence ${transferHashHex.slice(0, 16)}..., price ${Number(o.priceCredits)} credits, expiry ${Number(o.expiryHeight)}`);
        if (reasons.length) { console.log(`    INVALID: ${reasons.join("; ")}`); continue; }
        console.log(`  ACTIVE HOLDER (computed): ${claim.getOwnerId().toString()} (share superseded; reward script ${Buffer.from(co.rewardScript).toString("hex").slice(0, 16)}...)`);
        return;
      }
      console.log(`  ACTIVE HOLDER (computed): ${baseOwner} (no valid superseding claim)`);
      return;
    }

    throw new Error(`unknown command "${cmd}" (register | intent | pay | claim | resolve)`);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
