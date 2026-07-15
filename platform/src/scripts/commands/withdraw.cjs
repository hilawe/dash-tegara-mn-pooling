module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      const [duffsStr, toAddressArg] = args;
      // canonical decimal, parsed as BigInt so an unsafe Number can never round the
      // amount (review finding B7); the SDK takes a Number, so safety is re-checked
      // at the conversion boundary
      if (!/^[1-9][0-9]*$/.test(duffsStr || "")) {
        throw new Error("usage: withdraw <amountDuffs, canonical positive integer> [address]");
      }
      const MAX_SUPPLY_DUFFS = 2100000000000000n; // 21M DASH
      const CREDITS_PER_DUFF = 1000n;
      const amountDuffsBig = BigInt(duffsStr);
      if (amountDuffsBig > MAX_SUPPLY_DUFFS) throw new Error("amount exceeds the coin supply");
      const amountCredits = amountDuffsBig * CREDITS_PER_DUFF;
      if (amountCredits > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("amount too large for the SDK's Number interface");
      }
      const amountDuffs = Number(amountDuffsBig);

      const account = await client.getWalletAccount();
      // default to a fresh address of OUR OWN wallet so the arrival is observable here;
      // the production default is the funder's recorded l1RewardScript on their share
      const toAddress = toAddressArg || account.getUnusedAddress().address;
      // arrival is only observable for the wallet's own default destination; an
      // EXPLICITLY supplied address is treated as external (this wallet cannot prove
      // ownership of an arbitrary address, review finding B1). The destination's
      // existing outpoints are snapshotted BEFORE submitting so a reused address can
      // never fake an arrival with an old output (review finding B2).
      const observable = !toAddressArg;
      const outpointsAt = (addr) => new Set(account.getUTXOS()
        .filter((u) => u.address && u.address.toString() === addr)
        .map((u) => `${u.txId}:${u.outputIndex}`));
      const preOutpoints = outpointsAt(toAddress);

      const identity = await client.platform.identities.get(myId);
      const before = BigInt(identity.getBalance());
      if (amountCredits > before) {
        throw new Error(`withdrawal of ${amountCredits} credits exceeds the balance ${before}`);
      }
      const walletBefore = account.getTotalBalance();

      console.log(`${who} withdraws ${DASHfmt(amountDuffs)} DASH (${amountCredits} credits) to ${toAddress}`);
      console.log("submitting the credit-withdrawal transition (signed by the funder's own transfer key) ...");
      await client.platform.identities.withdrawCredits(identity, Number(amountCredits), { toAddress });

      const after = BigInt((await client.platform.identities.get(myId)).getBalance());
      const debited = before - after;
      console.log(`credits debited: ${debited} (withdrawal ${amountCredits} plus the transition fee)`);
      if (debited < amountCredits) throw new Error("identity balance fell by less than the withdrawal amount");

      // an EXTERNAL destination cannot be observed from this wallet: say so honestly and
      // stop with success (the transition is accepted and the credits are debited; the
      // quorum-signed asset-unlock pays the address within a few core blocks)
      if (!observable) {
        console.log(`\n=== WITHDRAWAL SUBMITTED: the credits are debited and the transition is accepted. ` +
          `${toAddress} is not observable from this wallet; verify arrival on-chain (a few core blocks) ===`);
        return;
      }

      // the asset-unlock is quorum-signed and lands on L1 within a few core blocks; only
      // a NEW outpoint at the destination counts as arrival
      console.log("waiting for the L1 asset-unlock to pay the address (new outpoint only) ...");
      const deadline = Date.now() + 360000;
      let received = null;
      while (Date.now() < deadline) {
        const fresh = account.getUTXOS().filter((u) =>
          u.address && u.address.toString() === toAddress
          && !preOutpoints.has(`${u.txId}:${u.outputIndex}`));
        if (fresh.length > 0) { received = fresh[0]; break; }
        await new Promise((r) => setTimeout(r, 5000));
      }
      if (received === null) {
        console.log("no NEW outpoint at the destination within the wait window. The transition was " +
          "accepted and the credits are debited; the asset-unlock may still be in the quorum-signing " +
          "queue. Re-check the address later (this command cannot yet confirm either way).");
        process.exitCode = 1;
        return;
      }
      const receivedDuffs = received.satoshis;
      const walletAfter = account.getTotalBalance();
      console.log(`L1 arrival: ${DASHfmt(receivedDuffs)} DASH at ${toAddress} ` +
        `(new outpoint ${received.txId}:${received.outputIndex}; any difference from ` +
        `${DASHfmt(amountDuffs)} is the asset-unlock's own core fee)`);
      console.log(`wallet balance: ${DASHfmt(walletBefore)} -> ${DASHfmt(walletAfter)} DASH`);
      if (receivedDuffs <= 0 || receivedDuffs > amountDuffs) {
        throw new Error("received amount outside the expected range");
      }
      console.log(`\n=== WITHDRAWAL OK: ${who}'s credits left Platform as L1 DASH at their own address, ` +
        "no operator involved ===");
      return;
};
