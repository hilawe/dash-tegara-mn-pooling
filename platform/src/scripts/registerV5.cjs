/**
 * Publish the pool-ledger contract v5, the bundled schema revision the gap pass and the
 * 2026-07-12 review rounds accumulated. Derived from the registered v1 definition the
 * way registerV3/V4 are, carrying every v3/v4 change forward and adding four of its own,
 * so the diff against registerV4.cjs IS the design change:
 *
 *   1. pool carries a REQUIRED lifecycle `status` ("forming" | "live"). The G5 waiting
 *      room ran on a placeholder-hash convention because v4 had no lifecycle field; v5
 *      makes the state explicit and authoritative (the placeholder convention stays as
 *      belt and braces for the hash itself). Formation completion is the one legitimate
 *      forming -> live edge, made by the operator who owns the pool document.
 *   2. membershipRequest carries an OPTIONAL `provenance` ("fresh" | "compound" |
 *      "pledge"; absent reads as "fresh"). The compound ceiling stops being purely a
 *      client-side journal discipline: a compound join is now distinguishable ON the
 *      ledger, and a pledge is distinguishable from a churn join.
 *   3. membershipRequest carries an OPTIONAL `rewardScript` (an L1 output script the
 *      member supplies at pledge/join time). Formation completion uses the member's own
 *      script instead of deriving one from the operator-run wallet, which closes the
 *      review's "member-supplied reward script" note.
 *   4. votePreference carries an OPTIONAL `delegateTo` (a member identity id). With
 *      choice "delegate", it names whose direct choice this member's weight follows
 *      (one hop); without it, the weight follows the pool's leading direct choice.
 *      Resolution semantics live in tally.cjs and apply to the OUTCOME only; canonical
 *      rows keep the raw choice so myrow's self-authentication is unchanged.
 *
 * The v1..v4 ledgers and their ids are untouched; v5 is a fresh namespace persisted as
 * CONTRACT_V5_ID. Run like the other scripts; select it with LEDGER=v5.
 */
const path = require("path");
const { pathToFileURL } = require("url");
const Dash = require("dash");
const { installConsumedFilter } = require("./walletGuard.cjs");
const { loadEnv, saveEnv } = require("./envStore.cjs");

const HASH32 = { type: "array", byteArray: true, minItems: 32, maxItems: 32 };
const SCRIPT = { type: "array", byteArray: true, minItems: 1, maxItems: 34 };

(async () => {
  const contractUrl = pathToFileURL(path.join(__dirname, "../../dist/contract/poolLedger.js")).href;
  const { poolLedgerContract } = await import(contractUrl);

  const v5 = JSON.parse(JSON.stringify(poolLedgerContract));

  // ---- carried from v3/v4 (identical to registerV4.cjs) ----
  const accrualIndex = v5.rewardAccrual.indices.find((i) => i.name === "byPoolFunder");
  accrualIndex.unique = true;
  accrualIndex.properties = [
    { poolId: "asc" }, { funderId: "asc" }, { epochHeight: "asc" }, { kind: "asc" },
  ];
  v5.rewardAccrual.properties.shareBps = {
    type: "integer", minimum: 1, maximum: 10000, position: 4,
    description: "the funder's share at distribution time, so every epoch is reconstructible",
  };
  v5.rewardAccrual.properties.kind = {
    type: "string", enum: ["reward", "principal"], maxLength: 10, position: 5,
    description: "what this accrual distributes: an epoch reward or a dissolution's principal return",
  };
  v5.rewardAccrual.required.push("shareBps", "kind");
  v5.rewardAccrual.indices.push({
    name: "byPoolHeight", properties: [{ poolId: "asc" }, { epochHeight: "asc" }],
  });
  v5.settlement = {
    type: "object",
    documentsMutable: true,
    properties: {
      poolId: { ...HASH32, position: 0 },
      exitId: { ...HASH32, position: 1, description: "the exit membershipRequest document id" },
      joinId: { ...HASH32, position: 2, description: "the join membershipRequest document id" },
      leaverId: { ...HASH32, position: 3 },
      joinerId: { ...HASH32, position: 4 },
      amountDuffs: { type: "integer", minimum: 1, position: 5 },
      shareBps: { type: "integer", minimum: 1, maximum: 10000, position: 6 },
      contributionDuffs: { type: "integer", minimum: 0, position: 7 },
      phase: {
        type: "string", maxLength: 20, position: 8,
        enum: ["prepared", "matched", "share-deleted", "share-recreated", "settled"],
      },
    },
    required: ["poolId", "exitId", "joinId", "leaverId", "joinerId", "amountDuffs",
      "shareBps", "phase", "$createdAt"],
    additionalProperties: false,
    indices: [
      { name: "byExit", properties: [{ exitId: "asc" }], unique: true },
      { name: "byJoin", properties: [{ joinId: "asc" }], unique: true },
      { name: "byPoolPhase", properties: [{ poolId: "asc" }, { phase: "asc" }] },
    ],
  };

  // ---- new in v5 ----
  // 1. the pool lifecycle field
  v5.pool.properties.status = {
    type: "string", enum: ["forming", "live"], maxLength: 10, position: 5,
    description: "the pool lifecycle: forming (pledge book open, no node yet) or live (a real node backs it)",
  };
  v5.pool.required.push("status");
  // 2 + 3. join provenance and the member-supplied reward script (both optional)
  v5.membershipRequest.properties.provenance = {
    type: "string", enum: ["fresh", "compound", "pledge"], maxLength: 10, position: 4,
    description: "what funded this request: new capital (fresh, the default when absent), compounded rewards, or a formation pledge",
  };
  v5.membershipRequest.properties.rewardScript = {
    ...SCRIPT, position: 5,
    description: "the member's own L1 reward script, supplied at pledge/join time so formation never derives one for them",
  };
  // 4. targeted delegation
  v5.votePreference.properties.delegateTo = {
    ...HASH32, position: 3,
    description: "with choice delegate: the member identity whose direct choice this weight follows (one hop); absent means follow the pool's leading direct choice",
  };

  const env = loadEnv();
  if (!env.MNEMONIC || !env.IDENTITY_ID) {
    console.error("run register.cjs first (need MNEMONIC, IDENTITY_ID)");
    process.exit(1);
  }
  const clientOpts = {
    network: process.env.NETWORK || "testnet",
    wallet: { mnemonic: env.MNEMONIC },
  };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    installConsumedFilter(await client.getWalletAccount());
    const identity = await client.platform.identities.get(env.IDENTITY_ID);

    if (env.CONTRACT_V5_ID) {
      console.log("v5 contract already published:", env.CONTRACT_V5_ID);
      return;
    }
    console.log("publishing the pool-ledger v5 contract ...");
    const contract = await client.platform.contracts.create(v5, identity);
    await client.platform.contracts.publish(contract, identity);
    env.CONTRACT_V5_ID = contract.getId().toString();
    saveEnv(env);
    console.log("\n=== POOL-LEDGER V5 PUBLISHED ===");
    console.log("contract id:", env.CONTRACT_V5_ID);
    console.log("(pool status, join provenance, member reward scripts, delegateTo; run everything with LEDGER=v5)");
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
