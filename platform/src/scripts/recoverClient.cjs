/**
 * The seedless recovery client (the G9 follow-on the holistic round left as a residual):
 * act as a member's identity using ONLY the recovery keys added by `funderClient addkey`,
 * with NO wallet mnemonic present. This is what a member falls back to after losing the
 * primary seed.
 *
 * Keys come from the environment, never a mnemonic:
 *   RECOVER_ID           the member's Platform identity id
 *   RECOVER_AUTH_WIF     the AUTHENTICATION recovery key (signs documents)
 *   RECOVER_TRANSFER_WIF the TRANSFER recovery key (signs withdrawals), optional
 *
 * Subcommands:
 *   status                              prove control: fetch the identity and list its keys,
 *                                       confirming the recovery public keys are on-chain
 *   withdraw <duffs> <address>          move credits back to L1 with the transfer key
 *   vote <poolId> <proposalHash> <choice>   set a preference with the auth key
 *
 * HONEST STATE (updated 2026-07-13, the extracted library adopted): reads and the
 * ownership proof were validated live first, with writes blocked at the SDK's high-level
 * path ("Identity ... is not associated with wallet, or it's not synced"), because its
 * signer maps identity keys to HD-wallet keys, not to an imported raw key. This file then
 * carried an inline low-level signer as the proof of concept, and that signer was
 * extracted into the standalone library `dash-rawkey-signer` (its own clean-room-designed
 * project), which this file now CONSUMES for both writes. The library derives the
 * required key from the protocol (including a contract's per-document security level,
 * stricter than the inline version's purpose match), refuses wrong keys with typed
 * errors, and returns signed bytes; this file keeps the reads, the SDK nonce bumps, and
 * a broadcast through the PUBLIC DAPI client surface, so no `dash/build/...` internal
 * path remains. The library is a REAL dependency in package.json (review finding: the
 * dynamic import alone left it out of the package graph, absent from clean builds), so
 * a rebuilt tegara-sdk image carries it; until a rebuild, container runs mount the
 * host-installed copy at /app/node_modules/dash-rawkey-signer. See KEYS_AND_RECOVERY.md
 * for the validation record.
 */
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");

const PURPOSE = { 0: "authentication", 1: "encryption", 2: "decryption", 3: "transfer" };
const SECURITY = { 0: "master", 1: "critical", 2: "high", 3: "medium" };

(async () => {
  const cmd = process.argv[2] || "status";
  const args = process.argv.slice(3);
  const id = process.env.RECOVER_ID;
  const authWif = process.env.RECOVER_AUTH_WIF;
  const transferWif = process.env.RECOVER_TRANSFER_WIF;
  if (!id || !authWif) {
    console.error("need RECOVER_ID and RECOVER_AUTH_WIF (and RECOVER_TRANSFER_WIF for withdraw); " +
      "NO mnemonic is used or wanted here");
    process.exit(2);
  }
  // the signing key for this command: the transfer key for a withdrawal, the auth key
  // otherwise. Constructed as a single-private-key wallet, no HD seed.
  const wif = cmd === "withdraw" ? transferWif : authWif;
  if (cmd === "withdraw" && !transferWif) {
    console.error("withdraw needs RECOVER_TRANSFER_WIF (the transfer recovery key)");
    process.exit(2);
  }
  const clientOpts = { network: process.env.NETWORK || "testnet", wallet: { privateKey: wif } };
  // `vote` needs the pool-ledger contract id, and it arrives ONLY through
  // RECOVER_CONTRACT_ID. This matches the real recovery scenario (the member holds
  // their WIFs and the PUBLIC contract id, no local files), and it is what keeps this
  // key-handling process from reading the env file at all: the first version loaded the
  // whole store through loadEnv, and the "narrow parse" second version still pulled the
  // full file, mnemonic line included, into process memory before filtering (both
  // review catches, 2026-07-12). No command in this file reads any local file now.
  if (cmd === "vote") {
    const cid = process.env.RECOVER_CONTRACT_ID;
    if (!cid) {
      console.error("vote needs the pool-ledger contract id: set RECOVER_CONTRACT_ID " +
        "(a public value; on the devnet, copy the CONTRACT_*_ID for your LEDGER from the " +
        "operator's records)");
      process.exit(2);
    }
    clientOpts.apps = { poolLedger: { contractId: cid } };
  }
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);

  try {
    const identity = await client.platform.identities.get(id);
    if (!identity) throw new Error(`identity ${id} not found`);

    if (cmd === "status") {
      // key-possession check (review finding R5: an id-key byte match alone is not
      // enough): the matched key must ALSO carry the right purpose and must not be
      // disabled, and the wording claims possession, not a signed challenge. The
      // transfer key, when supplied, is checked separately against the same bar.
      const { PrivateKey } = Dash.Core;
      const net = process.env.NETWORK === "regtest" ? "testnet" : (process.env.NETWORK || "testnet");
      const pubOf = (w) => new PrivateKey(w, net).toPublicKey().toBuffer().toString("hex");
      const isDisabled = (k) => {
        if (typeof k.isDisabled === "function") return k.isDisabled();
        if (typeof k.getDisabledAt === "function") return k.getDisabledAt() != null;
        return false;
      };
      const wanted = [{ label: "AUTH", pub: pubOf(authWif), purpose: 0 }];
      if (transferWif) wanted.push({ label: "TRANSFER", pub: pubOf(transferWif), purpose: 3 });
      console.log(`identity ${id}`);
      console.log(`credits: ${identity.getBalance()}`);
      console.log("registered public keys:");
      for (const k of identity.getPublicKeys()) {
        const kh = Buffer.from(k.getData()).toString("hex");
        const w = wanted.find((x) => x.pub === kh);
        if (w) { w.key = k; }
        console.log(`  key ${k.getId()}: ${PURPOSE[k.getPurpose()] || k.getPurpose()} / ` +
          `${SECURITY[k.getSecurityLevel()] || k.getSecurityLevel()}` +
          `${isDisabled(k) ? " / DISABLED" : ""}${w ? `  <- MY ${w.label} RECOVERY KEY` : ""}`);
      }
      let allGood = true;
      for (const w of wanted) {
        if (!w.key) {
          console.log(`\nthe supplied ${w.label} recovery key does NOT match any key on this identity`);
          allGood = false;
        } else if (w.key.getPurpose() !== w.purpose) {
          console.log(`\nthe ${w.label} recovery key matched key ${w.key.getId()} but its purpose is ` +
            `${PURPOSE[w.key.getPurpose()] || w.key.getPurpose()}, not ${PURPOSE[w.purpose]}; ` +
            "it cannot authorize what this tool claims for it");
          allGood = false;
        } else if (isDisabled(w.key)) {
          console.log(`\nthe ${w.label} recovery key matched key ${w.key.getId()} but that key is ` +
            "DISABLED on the identity; it no longer authorizes anything");
          allGood = false;
        }
      }
      if (!allGood) {
        process.exitCode = 1;
      } else {
        const ids = wanted.map((w) => `${w.label.toLowerCase()} key ${w.key.getId()}`).join(", ");
        console.log(`\n=== SEEDLESS KEY POSSESSION CONFIRMED: ${ids} on-chain with the right purpose ` +
          "and not disabled, and this run holds the matching private key(s), no mnemonic present. " +
          "(A possession check, not a signed challenge; `vote` and `withdraw` exercise the keys.) ===");
      }
      return;
    }

    if (cmd === "vote" || cmd === "withdraw") {
      // THE SEEDLESS SIGNER, now the extracted library dash-rawkey-signer (the inline
      // low-level version this file used to carry was the proof of concept it was
      // extracted from). The library owns the whole authorization-and-signing story:
      // it derives the REQUIRED key from the protocol (TRANSFER for withdrawals,
      // AUTHENTICATION at the contract's security level for documents), matches the
      // supplied raw key against the identity snapshot, refuses wrong-purpose or
      // disabled keys with typed errors, clamps the core fee to the protocol floor,
      // and returns signed BYTES. This file keeps only the reads, the nonce bumps
      // (the SDK's nonce manager, as before), and the broadcast, which now goes
      // through the PUBLIC DAPI client surface instead of the SDK's internal helper,
      // so the last `dash/build/...` internal reach in this file is gone.
      // The library is ESM-only; dynamic import() is the CJS-compatible loader.
      const { createRawKeySigner, snapshotFromDashIdentity } = await import("dash-rawkey-signer");
      const platform = client.platform;
      await platform.initialize();
      const libNet = process.env.NETWORK === "regtest" ? "local"
        : (process.env.NETWORK === "mainnet" ? "mainnet" : "testnet");
      const signer = createRawKeySigner({ network: libNet });
      const snapshot = snapshotFromDashIdentity(identity, {
        network: libNet, protocolVersion: platform.protocolVersion,
      });
      // broadcast the signed bytes through the documented DAPI client API (the same
      // hash-then-broadcast-then-wait the SDK helper performs, minus the internal path).
      // The WAIT RESULT IS CHECKED (review must-fix: the first version discarded it, so
      // a transition the network rejected after acceptance into the queue would have
      // been reported as success): the result's error field carries the rejection, and
      // it becomes a loud throw exactly as the SDK's own helper treats it.
      const broadcastBytes = async (bytes) => {
        const buf = Buffer.from(bytes);
        const hash = require("crypto").createHash("sha256").update(buf).digest();
        const dapi = client.getDAPIClient();
        await dapi.platform.broadcastStateTransition(buf); // immediate rejections throw here
        const result = await dapi.platform.waitForStateTransitionResult(hash, { prove: true });
        if (result && result.error) {
          throw new Error(`the network REJECTED the transition (code ${result.error.code}): ` +
            `${result.error.message}`);
        }
      };
      console.log(`seedless ${cmd}: signing through dash-rawkey-signer, no mnemonic present`);

      if (cmd === "vote") {
        const [poolIdStr, proposalHex, choice] = args;
        if (!poolIdStr || !/^[0-9a-f]{64}$/i.test(proposalHex || "") || !choice) {
          throw new Error("usage: vote <poolId> <proposalHash 64-hex> <choice>");
        }
        const contractId = Identifier.from(process.env.RECOVER_CONTRACT_ID);
        const contract = await platform.contracts.get(contractId);
        if (!contract) throw new Error(`contract ${process.env.RECOVER_CONTRACT_ID} not found`);
        // create-or-replace, exactly like the normal vote command (review finding: one
        // preference per member per proposal is a unique index, so a recovered member
        // who already voted, or votes twice, must UPDATE in place, not collide). The
        // read decides which action the batch carries; the library builds and signs it.
        const proposal = Buffer.from(proposalHex, "hex");
        // byteArray document fields as plain Buffers, the natural form. The number-array
        // workaround this once carried is retired: the earlier failure was a
        // serialization divergence in the library's clone (a Buffer/Uint8Array byte field
        // serialized to an index-keyed map the network's DPP rejected, a plain array to
        // the compact form it accepts), pinned via the stack trace to broadcast, and
        // FIXED upstream in dash-rawkey-signer 0.3.1 (byte views normalize to the compact
        // wire form, so Buffer, Uint8Array, and array now serialize identically).
        // Live-reconfirmed with Buffers against 0.3.1.
        const data = {
          poolId: Identifier.from(poolIdStr).toBuffer(),
          proposalHash: proposal, choice,
        };
        const mine = (await platform.documents.get("poolLedger.votePreference", {
          where: [["poolId", "==", Identifier.from(poolIdStr)],
                  ["$ownerId", "==", identity.getId()],
                  ["proposalHash", "==", proposal]],
        }))[0];
        const action = mine
          ? { action: "replace", documentType: "votePreference",
              id: mine.getId().toBuffer(),
              revision: BigInt(mine.getRevision()), data }
          : { action: "create", documentType: "votePreference", data };
        const verb = mine ? `changed ${mine.toObject().choice} -> ${choice}` : `set to ${choice}`;
        const nonce = await platform.nonceManager
          .bumpIdentityContractNonce(identity.getId(), contractId);
        const signed = await signer.signDocumentBatch({
          identity: snapshot,
          privateKey: { wif },
          contract: contract.toBuffer(),
          actions: [action],
          nonceContext: { contractNonce: BigInt(nonce.toString()) },
        });
        await broadcastBytes(signed.bytes);
        console.log(`\n=== SEEDLESS VOTE OK: preference ${verb} (${action.action}), signed by the ` +
          "recovery key alone through dash-rawkey-signer ===");
      } else {
        const [duffsStr, toAddress] = args;
        if (!/^[1-9][0-9]*$/.test(duffsStr || "") || !toAddress) {
          throw new Error("usage: withdraw <duffs> <address>");
        }
        const credits = BigInt(duffsStr) * 1000n;
        const balance = BigInt(identity.getBalance());
        // the library preflights the amount against the snapshot balance and validates
        // the fee against the protocol's allowed sequence (its default IS the floor the
        // inline version clamped to); the minimum-withdrawal floor stays here because it
        // is an SDK-convention bound, not a protocol rule the library enforces
        if (credits < 190000n) throw new Error(`withdrawal below the 190000-credit minimum (${credits})`);
        const nonce = await platform.nonceManager.bumpIdentityNonce(identity.getId());
        const signed = await signer.signWithdrawal({
          identity: snapshot,
          privateKey: { wif },
          toAddress,
          amount: credits,
          nonceContext: { identityNonce: BigInt(nonce.toString()) },
        });
        await broadcastBytes(signed.bytes);
        const after = BigInt((await platform.identities.get(id)).getBalance());
        console.log(`credits: ${balance} -> ${after} (withdrawal ${credits} plus the transition fee)`);
        console.log(`\n=== SEEDLESS WITHDRAW OK: ${duffsStr} duffs to ${toAddress}, signed by the ` +
          "transfer recovery key alone through dash-rawkey-signer; the quorum-signed asset-unlock " +
          "pays out within a few core blocks ===");
      }
      return;
    }

    throw new Error(`unknown command "${cmd}" (status | vote | withdraw)`);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    // RECOVER_DEBUG=1 prints what the message alone hides: the error's constructor
    // name and the full stack, which names the module that actually threw (the
    // maintainer-requested pin-down for the byteArray failure)
    if (process.env.RECOVER_DEBUG === "1" && e) {
      console.error("DEBUG constructor:", e.constructor && e.constructor.name);
      console.error("DEBUG stack:", e.stack || "(no stack)");
    }
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
