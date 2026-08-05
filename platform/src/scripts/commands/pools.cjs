const lifecycle = require("../poolLifecycle.cjs");
const { hasImmutablePool } = require("../envStore.cjs");
const { checkReceiptAgainstPool } = require("../receiptPoolCheck.cjs");

module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const pools = await fetchAll(client, "poolLedger.pool");
      console.log(`${pools.length} pools on the ledger:`);
      for (const p of pools) {
        const o = p.toObject();
        const shares = await client.platform.documents.get("poolLedger.share", {
          where: [["poolId", "==", p.getId()]],
        });
        const bps = shares.reduce((s, d) => s + Number(d.toObject().shareBps), 0);
        const mine = shares.some((d) => d.getOwnerId().toString() === myId) ? "  <- member" : "";
        // the node column must not silently empty on an immutable ledger, where the pool
        // names no node and only a verified completion receipt does. A blank would read to a
        // member as "this pool backs nothing", which is a different claim from "the ledger
        // does not tell me". A member listing pools does not act on the node, so it reports.
        let node = lifecycle.backingNode({ pool: o });
        if (hasImmutablePool()) {
          const rd = (await client.platform.documents.get("poolLedger.completionReceipt",
            { where: [["poolId", "==", p.getId()]] }))[0] || null;
          const ro = rd ? rd.toObject() : null;
          const okR = ro ? checkReceiptAgainstPool({ contractId: activeContractId(env), receipt: ro,
            pool: o, poolId: p.getId(),
            // both documents are in hand in this listing, so duty 6 is checked
            receiptOwnerId: rd.getOwnerId().toString(),
            poolOwnerId: p.getOwnerId().toString() }).ok === true : false;
          node = lifecycle.backingNode({ pool: o, receipt: ro, receiptOk: okR });
        }
        const nodeLabel = node.known ? `node ${node.hex.slice(0, 12)}...` : "node UNKNOWN";
        console.log(`  ${p.getId().toString()}  ${nodeLabel} ` +
          `slot ${o.slotIndex}, fee ${Number(o.operatorFeeBps)} bps, shares ${bps}/10000${mine}`);
      }
      return;
};
