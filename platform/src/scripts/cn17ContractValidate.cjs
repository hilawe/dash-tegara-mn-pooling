/**
 * a soundness-review finding probe, contract-authoring half (OFFLINE, authoritative). Uses the project's own
 * validation standard (`dpp.dataContract.create`, the same wasm-dpp validation the network
 * applies, per validate.cjs and the platform README) to establish, without needing a live
 * Platform (which is currently halted on this devnet), whether a data contract can mark a
 * document type transferable + direct-purchase, and to PIN the exact accepted semantics of
 * the transferable / tradeMode document-type keywords by probing their value ranges.
 *
 * Run: docker run --rm -e NETWORK=regtest -v "$PWD/src:/app/src" tegara-sdk \
 *        node src/scripts/cn17ContractValidate.cjs
 */
const Dash = require("dash");
const ctorOf = (e) => (e && e.constructor && e.constructor.name) || "";
const msgOf = (e) => (e && e.message) || (ctorOf(e) !== "Object" && ctorOf(e)) || String(e);

const shareLike = (extra) => ({
  type: "object",
  ...extra,
  properties: {
    poolId: { type: "array", byteArray: true, minItems: 32, maxItems: 32, position: 0 },
    shareBps: { type: "integer", minimum: 1, maximum: 10000, position: 1 },
    contributionDuffs: { type: "integer", minimum: 1, position: 2 },
    l1RewardScript: { type: "array", byteArray: true, minItems: 1, maxItems: 34, position: 3 },
  },
  required: ["poolId", "shareBps", "contributionDuffs", "$createdAt"],
  additionalProperties: false,
  indices: [{ name: "byPool", properties: [{ poolId: "asc" }, { $createdAt: "asc" }] }],
});

(async () => {
  const client = new Dash.Client({ network: process.env.NETWORK || "testnet" });
  try {
    await client.platform.initialize();
    const dpp = client.platform.dpp;
    const ownerId = Buffer.alloc(32, 7);
    const validate = (schema) => {
      try { const dc = dpp.dataContract.create(ownerId, 1n, schema); return { ok: true, id: dc.getId().toString() }; }
      catch (e) { return { ok: false, err: `${ctorOf(e)}: ${msgOf(e).slice(0, 160)}` }; }
    };

    console.log("=== 1. a transferable + direct-purchase `share` document type validates? ===");
    const r1 = validate({ share: shareLike({ transferable: 1, tradeMode: 1 }) });
    console.log(r1.ok ? `  OK, contract id ${r1.id}` : `  REJECTED ${r1.err}`);

    console.log("\n=== 2. control: the same `share` WITHOUT the keywords ===");
    const r2 = validate({ share: shareLike({}) });
    console.log(r2.ok ? `  OK, contract id ${r2.id}` : `  REJECTED ${r2.err}`);

    console.log("\n=== 3. pin the accepted VALUE RANGE of `transferable` (tradeMode fixed at 1) ===");
    for (const v of [0, 1, 2, 3]) {
      const r = validate({ share: shareLike({ transferable: v, tradeMode: 1 }) });
      console.log(`  transferable:${v} -> ${r.ok ? "accepted" : "rejected"}${r.ok ? "" : "  (" + r.err + ")"}`);
    }

    console.log("\n=== 4. pin the accepted VALUE RANGE of `tradeMode` (transferable fixed at 1) ===");
    for (const v of [0, 1, 2, 3]) {
      const r = validate({ share: shareLike({ transferable: 1, tradeMode: v }) });
      console.log(`  tradeMode:${v} -> ${r.ok ? "accepted" : "rejected"}${r.ok ? "" : "  (" + r.err + ")"}`);
    }

    console.log("\n=== 5. tradeMode:1 (direct purchase) WITHOUT transferable - accepted? ===");
    const r5 = validate({ share: shareLike({ tradeMode: 1 }) });
    console.log(r5.ok ? `  OK` : `  REJECTED ${r5.err}`);

    console.log("\n=== 6. can an ExtendedDocument of a tradeMode type carry a $price system field? ===");
    try {
      const dc = dpp.dataContract.create(ownerId, 1n, { share: shareLike({ transferable: 1, tradeMode: 1 }) });
      const doc = dpp.document.create(dc, ownerId, "share",
        { poolId: Buffer.alloc(32, 1), shareBps: 4000, contributionDuffs: 100000000, l1RewardScript: Buffer.alloc(25, 2) });
      let priceSet = "n/a";
      try { doc.set("$price", 500000000000n); priceSet = `set ok, read back ${doc.get("$price")}`; }
      catch (e) { priceSet = `set rejected: ${ctorOf(e)}: ${msgOf(e).slice(0,120)}`; }
      console.log(`  $price on the document object: ${priceSet}`);
    } catch (e) { console.log(`  doc build failed: ${msgOf(e)}`); }
  } catch (e) {
    console.error("VALIDATE PROBE ERROR:", msgOf(e));
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 6).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
