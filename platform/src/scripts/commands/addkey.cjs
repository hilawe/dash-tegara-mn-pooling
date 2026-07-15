module.exports = async (ctx) => {
  const { client, env, args, cmd, who, whoIdKey, DASHfmt, short, Identifier, Dash, fetchAll,
    updateEnvKey, activeContractId, activeCastId, isV3, isV5, journal, journalContract,
    getPool, myShares, myRequests, isMyAccrual, myAccruals, requestExists, earnedRewardsBig,
    autopayKeyOf, watchKeyOf, depositOwnFunds, runAutopaySweep } = ctx;
  const myId = ctx.myId;
      // The G9 recovery-key story, built: add a SECOND authentication key to my
      // identity, generated OUTSIDE the wallet seed, so losing the primary seed no
      // longer strands the identity (the new key keeps signing for the same identity,
      // same shares, same credits, no migration). The honest caveat from the doc
      // stands: a second key doubles the theft surface as well as halving the loss
      // risk; the printed key must be stored SEPARATELY from the seed or it adds
      // nothing.
      // the update transition carries keys WITH their self-signature slot, hence the
      // WithWitness class (the SDK signs the witness with the matching private key)
      const { IdentityPublicKeyWithWitness } = require("@dashevo/wasm-dpp");
      const identity = await client.platform.identities.get(myId);
      const existing = identity.getPublicKeys();
      const nextKeyId = Math.max(...existing.map((k) => k.getId())) + 1;
      const recoveryPriv = new Dash.Core.PrivateKey(undefined,
        (process.env.NETWORK || "testnet") === "regtest" ? "testnet" : (process.env.NETWORK || "testnet"));
      const pubData = recoveryPriv.toPublicKey().toBuffer();
      const authKey = new IdentityPublicKeyWithWitness(1);
      authKey.setId(nextKeyId);
      authKey.setData(pubData);
      // AUTHENTICATION purpose at HIGH security: signs documents and ordinary state
      // transitions; it deliberately does NOT replace the master key (identity-update
      // rights stay with the original seed)
      authKey.setPurpose(0); // AUTHENTICATION
      authKey.setSecurityLevel(2); // HIGH
      // a SECOND recovery key with TRANSFER purpose (holistic-round F9, review):
      // without one, losing the seed leaves the member permanently unable to move
      // credits back to L1, which defeats the recovery story's point. Its own private
      // key, also generated outside the seed.
      const transferPriv = new Dash.Core.PrivateKey(undefined,
        (process.env.NETWORK || "testnet") === "regtest" ? "testnet" : (process.env.NETWORK || "testnet"));
      const transferKey = new IdentityPublicKeyWithWitness(1);
      transferKey.setId(nextKeyId + 1);
      transferKey.setData(transferPriv.toPublicKey().toBuffer());
      transferKey.setPurpose(3); // TRANSFER
      transferKey.setSecurityLevel(1); // CRITICAL, what withdrawal transitions demand

      console.log(`adding recovery keys ${nextKeyId} (authentication) and ${nextKeyId + 1} (transfer) ` +
        `to ${who}'s identity ${myId} ...`);
      let transferAdded = true;
      try {
        await client.platform.identities.update(identity, { add: [authKey, transferKey] },
          { [nextKeyId]: recoveryPriv, [nextKeyId + 1]: transferPriv });
      } catch (e) {
        // fall back to the authentication key alone rather than losing the whole
        // recovery story to a transfer-key rule on this Platform version; the
        // limitation is then printed, never papered over
        console.log(`the two-key update was refused (${(e && e.message) || e}); retrying with the ` +
          "authentication key alone");
        transferAdded = false;
        const freshIdentity = await client.platform.identities.get(myId);
        await client.platform.identities.update(freshIdentity, { add: [authKey] },
          { [nextKeyId]: recoveryPriv });
      }

      const after = await client.platform.identities.get(myId);
      if (!after.getPublicKeys().find((k) => k.getId() === nextKeyId)) {
        throw new Error("the update was accepted but the key does not read back; investigate");
      }
      console.log(`identity now carries ${after.getPublicKeys().length} public keys`);
      console.log("\n=== RECOVERY KEYS ADDED. Write these down and store them AWAY from the wallet seed ===");
      console.log(`  authentication key (WIF): ${recoveryPriv.toWIF()}`);
      if (transferAdded) console.log(`  transfer key (WIF): ${transferPriv.toWIF()}`);
      // the capability statement is exact, never broader than the keys' purposes and
      // security levels actually authorize (independent-review findings, both rounds)
      console.log("  what they CAN do if the seed is lost: the authentication key signs this");
      console.log("    identity's documents and HIGH-level transitions (shares, requests, preferences)" +
        (transferAdded ? ";" : ""));
      if (transferAdded) {
        console.log("    the transfer key signs credit withdrawals back to L1");
      } else {
        console.log("  NOT RECOVERED on this Platform version: credit withdrawals (the transfer key");
        console.log("    was refused above); losing the seed then PERMANENTLY strands the credits' L1 exit");
      }
      console.log("  what they CANNOT do: manage identity keys (the master key stays with the seed)");
      console.log("  anyone holding them can act on ledger state as this identity, so guard them like a seed");
      return;
};
