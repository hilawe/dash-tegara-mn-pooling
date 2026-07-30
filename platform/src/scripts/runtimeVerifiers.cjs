/**
 * runtimeVerifiers - the CRYPTOGRAPHIC half the offline build deferred.
 *
 * The offline modules derive and serialize; the registry
 * (docs/schema/auditEnvelope.v1.registry.json) names a verifier per component and states
 * plainly that a component stays TRUSTED_SOURCE until its verifier RUNS AND SUCCEEDS.
 * This module is that layer, plus the harness that turns a successful run into the
 * ATTESTATION `envelopeWriter` requires.
 *
 * WHAT IS IMPLEMENTED HERE, AND WHAT IS HONESTLY BLOCKED.
 * Three verifiers need nothing but the standard library and are implemented COMPLETELY:
 *   verifyIdentifierConversion  the proTxHash byte-order conversion and, in
 *                               FIRST_APPEARANCE mode, that the retained ProRegTx's txid
 *                               IS the pool proTxHash
 *   verifyTransitionHashes      every ownership hop's transitionHash equals sha256 of the
 *                               retained committed bytes at that hop's position
 *   verifyCheckpointRecognition the ed25519 signature over sha256(signedPayloadBytes)
 *                               under the FIXED deployment authority, AND the payload's
 *                               embedded domain tag re-derived from the envelope's own
 *                               network fields (so a checkpoint copied from another chain
 *                               or another devnet fails here)
 * verifyCoreWalk is IMPLEMENTED and no longer among the blocked list below (round 6, MINOR: this
 * header still called it blocked while the same file placed it in IMPLEMENTED). It performs the
 * checks whose evidence the record carries, including the diff-chain walk with list STATE, the
 * list root against the coinbase commitment, and the coinbase's binding into its block. It still
 * returns ran:false, because the endpoint ChainLock check and the header-chain ancestry check have
 * not run, and it reports what it PROVED alongside what remains.
 *
 * The rest are BLOCKED on a named external dependency that does not exist in this tree.
 * They are declared, not silently missing, and they return `{ran:false, blockedOn}` so a
 * caller can never mistake absence for success:
 *   verifyBasePackage                    the SML root computation over a pinned real capture
 *                                        (the ChainLock signature half is implemented and
 *                                        verified against a real vector, chainLockVerify.cjs)
 *   verifyPlatformCommits                the real Tenderdash protobuf header/commit codec
 *   verifyDecodeDispositions             the decoder bundle itself (build artifact)
 *   verifyBookConformance                retrieved, authenticated pool-document state
 *   verifyConservation                   the owner-payout derivation from L1 state
 *   verifyL1BackingAtHeight              structurally barred in v1 (empty evidence set)
 *   verifyReceiptDuties                  structurally barred in v1 (empty evidence set)
 *
 * A blocked verifier NEVER yields an attestation, so every component it covers stays
 * TRUSTED_SOURCE and the aggregate stays capped, which is exactly the disclosed state.
 */
"use strict";

const crypto = require("crypto");
const { canonicalize } = require("./canonicalJson.cjs");
const { displayToRaw, assertHex32 } = require("./proTxHashCodec.cjs");
const {
  parseMnListDiff, computeListRoot, readCbTxPayload, parseStandaloneEntry, applyDiffToList,
  extractMerkleMatches, indexHeaderChain, blockHashOf, Reader,
} = require("./mnListDiffCodec.cjs");

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const sha256d = (b) => sha256(sha256(b));
/**
 * STRICT hex decode (round 5, MAJOR). `Buffer.from(value, "hex")` stops at the first
 * character that is not hex and returns what it managed to read, with no error and no
 * indication that it truncated. `Buffer.from("zz", "hex")` is an EMPTY buffer, and
 * `Buffer.from("aabZ", "hex")` is one byte. That turned malformed evidence into a verifier
 * SUCCESS: with rawBytes "zz" decoding to nothing, verifyTransitionHashes compared the hash
 * of empty bytes against committed hashes set to the hash of empty bytes and reported
 * ran:true, ok:true over evidence it never actually read. A verifier that cannot tell
 * malformed input from empty input cannot be trusted to report what it verified, so every
 * hex decode in this module goes through this function.
 */
function hexBuf(h, what = "a hex field") {
  if (typeof h !== "string" || h.length % 2 !== 0 || !/^(?:[0-9a-f]{2})*$/.test(h)) {
    throw new Error(`runtimeVerifiers: ${what} is not an even-length lowercase hex string`);
  }
  return Buffer.from(h, "hex");
}

const V2_LABEL = Buffer.from("tegara-fixedslot-checkpoint-v2", "utf8");
const IDENTITY_LABEL = Buffer.from("TegaraCoreChainIdentity/v1", "utf8");
const CORE_NETWORK_CODE = { mainnet: 0, testnet: 1, devnet: 2, regtest: 3 };

/** a verifier result: ran + ok, or ran:false with the dependency that blocks it */
const OK = (detail) => ({ ran: true, ok: true, detail });
const BAD = (reason) => ({ ran: true, ok: false, reason });
const BLOCKED = (blockedOn) => ({ ran: false, ok: false, blockedOn });

/**
 * The DERIVED Core chain identity (a soundness review), never serialized: the label, a one-byte
 * network code, the height-zero genesis bytes, and either the devnet height-one genesis
 * or 32 zero bytes. Hash fields are RPC-display hex decoded LEFT TO RIGHT with no
 * reversal (the pinned byte convention).
 */
function coreChainIdentityHash(network) {
  const code = CORE_NETWORK_CODE[network.coreNetwork];
  if (code === undefined) throw new Error(`runtimeVerifiers: unknown coreNetwork ${network.coreNetwork}`);
  const genesis = hexBuf(assertHex32(network.coreGenesisBlockHash, "coreGenesisBlockHash"));
  const devnetH1 = network.coreDevnetGenesisBlockHash
    ? hexBuf(assertHex32(network.coreDevnetGenesisBlockHash, "coreDevnetGenesisBlockHash"))
    : Buffer.alloc(32);
  return sha256(Buffer.concat([IDENTITY_LABEL, Buffer.from([code]), genesis, devnetH1]));
}

/** the checkpoint v2 domain tag, re-derived from the envelope's own fields */
function v2DomainTag(chainIdentity, authorityPubKey) {
  return sha256(Buffer.concat([V2_LABEL, chainIdentity, authorityPubKey]));
}

// ---------------------------------------------------------------------------
// IMPLEMENTED VERIFIERS
// ---------------------------------------------------------------------------

/**
 * verifyIdentifierConversion - the identity bindings, complete.
 * Re-derives the raw consensus form from the serialized display hash, and under
 * FIRST_APPEARANCE re-derives the ProRegTx txid and requires it to EQUAL the pool
 * proTxHash (the registration transaction really is this node's).
 */
function verifyIdentifierConversion(env) {
  try {
    const raw = displayToRaw(env.poolProTxHash);
    if (raw.length !== 32) return BAD("poolProTxHash did not convert to 32 raw bytes");
    if (Buffer.from(raw).reverse().toString("hex") !== env.poolProTxHash) {
      return BAD("the display<->raw conversion does not round-trip");
    }
    const bp = env.basePackage;
    if (bp.kind === "rooted" && bp.baseMode === "FIRST_APPEARANCE") {
      const txid = sha256d(hexBuf(bp.firstAppearance.proRegTxRaw, "firstAppearance.proRegTxRaw"));
      const display = Buffer.from(txid).reverse().toString("hex");
      if (display !== env.poolProTxHash) {
        return BAD(`the retained ProRegTx txid ${display.slice(0, 16)}... is not the pool proTxHash`);
      }
      return OK("conversion round-trips; the ProRegTx txid IS the pool identity");
    }
    return OK("conversion round-trips (no FIRST_APPEARANCE registration to bind)");
  } catch (e) {
    return BAD((e && e.message) || String(e));
  }
}

/**
 * verifyTransitionHashes - every ownership hop is bound to the retained committed bytes
 * at its own position: transitionHash == sha256(rawBytes of the transaction at
 * (platformHeight, txIndex)). A hop whose position holds different bytes fails.
 */
function verifyTransitionHashes(env) {
  try {
    const byPos = new Map();
    for (const row of env.coverage.platformLedger) {
      for (const tx of row.txs) byPos.set(`${row.height}/${tx.txIndex}`, tx);
    }
    let checked = 0;
    for (const slot of env.slots) {
      for (const hop of slot.ownershipChain) {
        const p = hop.position;
        const tx = byPos.get(`${p.platformHeight}/${p.txIndex}`);
        if (!tx) return BAD(`no retained transaction at ${p.platformHeight}/${p.txIndex}`);
        const digest = sha256(hexBuf(tx.rawBytes, `rawBytes at ${p.platformHeight}/${p.txIndex}`)).toString("hex");
        if (digest !== tx.committedHash) {
          return BAD(`committedHash at ${p.platformHeight}/${p.txIndex} is not sha256(rawBytes)`);
        }
        if (hop.transitionHash !== digest) {
          return BAD(`transitionHash at ${p.platformHeight}/${p.txIndex} does not bind the retained bytes`);
        }
        checked++;
      }
    }
    return OK(`${checked} ownership hop(s) bound to retained committed bytes`);
  } catch (e) {
    return BAD((e && e.message) || String(e));
  }
}

/**
 * verifyCheckpointRecognition - THE SIGNATURE, plus chain-identity domain separation.
 *
 * For every checkpoint: the signer must be the FIXED deployment authority; the ed25519
 * signature must verify over sha256(signedPayloadBytes) under that key; the checkpointId
 * must equal that same digest; and the payload's EMBEDDED domain tag (bytes 4..36) must
 * equal the tag re-derived from the ENVELOPE's own network fields. The last check is what
 * makes a checkpoint copied from another chain, or from another devnet sharing a base
 * genesis, fail here rather than pass as evidence (a soundness review).
 *
 * THE DEVNET HEIGHT-ONE BLOCK duty IS PERFORMED when a Core node is supplied (round 5, MINOR:
 * this header still said the duty was blocked after the implementation landed, which is the
 * kind of stale claim the whole review cycle exists to catch). Given a node exposing
 * getBlockHexByHeight, the block is retrieved and its hash, parent, proof of work and coinbase
 * devnet-name commitment are checked, with the merkle root binding the coinbase to the verified
 * hash. WITHOUT such a node the component stays BLOCKED and reports what it did prove, so a
 * missing Core node can never read as a discharged duty.
 */
/**
 * Read the single coinbase transaction of a devnet genesis block and return its txid plus the
 * devnet-name commitment from its scriptSig.
 *
 * Dash writes that block as ONE transaction whose scriptSig is the BIP34 height push followed
 * by a push of the devnet name (8c9f166a3:src/chainparams.cpp:43-64). A genesis block with more
 * than one transaction is refused rather than merkle-proved, because the single-transaction case
 * is the only one where the merkle root IS the coinbase txid, and that identity is what binds
 * the coinbase to the verified header hash.
 *
 * Returns { txid, nameCommitment } or { error }.
 */
function readGenesisCoinbase(block) {
  try {
    // ONE COMPACTSIZE READER IN THE BUILD (round 8, MUST-FIX, a soundness-review finding). This function used to keep
    // its own readVarInt, which applied neither the canonical-width rule nor MAX_SIZE. A block
    // whose transaction count, input or output count, or any script length used a wider-than-
    // needed encoding parsed cleanly here, while Dash Core refuses those same bytes in
    // ReadCompactSize [8c9f166a3:src/serialize.h:288-317,
    // 8c9f166a3:src/primitives/transaction.h:242-250,320-330]. The verifier could then return
    // ran:true, ok:true for a block outside the network's serialized block domain.
    //
    // The second reader is DELETED rather than taught the rules. A duplicate reader is how the
    // divergence arose, and the same lesson has now been paid for three times in this build
    // (two serializers, the registry mapping, and this). `Reader` is the codec's only CompactSize
    // reader, so routing through it means the height-one path cannot drift from the wire domain
    // again. Its `need` also turns every short read into a named error instead of a short buffer,
    // which removes the separate truncation checks this function used to carry.
    const r = new Reader(block);
    r.off = 80;                                 // the 80-byte header is verified by the caller
    const txCount = r.varint("block transaction count");
    if (txCount !== 1) {
      return { error: `count is ${txCount}; a genesis block carries exactly one transaction` };
    }
    const txStart = r.off;
    r.read(4, "transaction version and type");
    const vinCount = r.varint("tx input count");
    if (vinCount !== 1) return { error: "input count is not 1" };
    // THE INPUT MUST BE A COINBASE INPUT (round 6, MUST-FIX). This advanced past the prevout
    // without looking at it, so a one-input ORDINARY transaction with a suitably shaped script was
    // described as a coinbase. A coinbase spends a null prevout: 32 zero bytes and index 0xffffffff.
    const prevoutHash = r.read(32, "prevout hash");
    const prevoutIndex = r.u32("prevout index");
    if (!prevoutHash.equals(Buffer.alloc(32)) || prevoutIndex !== 0xffffffff) {
      return { error: "input does not spend a null prevout, so it is not a coinbase" };
    }
    const scriptSig = r.read(r.varint("scriptSig length"), "scriptSig");
    r.read(4, "sequence");
    const voutCount = r.varint("tx output count");
    for (let i = 0; i < voutCount; i++) {
      r.read(8, `output ${i} value`);
      r.read(r.varint(`output ${i} script length`), `output ${i} script`);
    }
    r.read(4, "locktime");
    // THE BLOCK MUST END HERE (round 6, MUST-FIX). The parse stopped after the first transaction
    // without requiring the buffer to be consumed, so a valid one-transaction block followed by
    // trailing bytes was accepted. A genesis block is exactly one transaction and nothing else.
    if (r.off !== block.length) {
      return { error: `carries ${block.length - r.off} trailing byte(s) after its single transaction` };
    }
    const txid = sha256d(block.subarray(txStart, r.off));

    // scriptSig: the BIP34 height push, then the name push. Dash emits `CScript() << 1`, which
    // is OP_1 (0x51); a one-byte push of 0x01 is accepted as the equivalent encoding.
    let sp = 0;
    if (scriptSig[sp] === 0x51) sp += 1;
    else if (scriptSig[sp] === 0x01 && scriptSig[sp + 1] === 0x01) sp += 2;
    else return { error: "scriptSig does not begin with the BIP34 height-one push" };
    const pushOp = scriptSig[sp];
    if (pushOp === undefined || pushOp === 0 || pushOp > 0x4b) {
      return { error: "scriptSig carries no direct devnet-name push after the height" };
    }
    const name = scriptSig.subarray(sp + 1, sp + 1 + pushOp);
    if (name.length !== pushOp) return { error: "the devnet-name push is truncated" };
    return { txid, nameCommitment: name };
  } catch (e) {
    return { error: `could not be parsed (${(e && e.message) || e})` };
  }
}

function verifyCheckpointRecognition(env, { coreNode } = {}) {
  try {
    const authorityHex = env.checkpointAuthority.publicKey;
    const authority = hexBuf(assertHex32(authorityHex, "checkpointAuthority.publicKey"));
    const identity = coreChainIdentityHash(env.network);
    const expectedTag = v2DomainTag(identity, authority);
    // ed25519 raw public keys are wrapped in the SPKI prefix Node's KeyObject expects
    const spki = Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"), authority]);
    const key = crypto.createPublicKey({ key: spki, format: "der", type: "spki" });

    for (const cp of env.checkpoints) {
      if (cp.signerPublicKey !== authorityHex) {
        return BAD(`checkpoint ${cp.epochId} is not signed by the fixed deployment authority`);
      }
      if (cp.algorithm !== "ed25519") return BAD(`checkpoint ${cp.epochId} names a non-ed25519 algorithm`);
      const payload = hexBuf(cp.signedPayloadBytes, `checkpoint ${cp.epochId} signedPayloadBytes`);
      const digest = sha256(payload);
      if (digest.toString("hex") !== cp.checkpointId) {
        return BAD(`checkpoint ${cp.epochId}: checkpointId is not sha256(payload)`);
      }
      const embeddedTag = payload.subarray(4, 36);
      if (!embeddedTag.equals(expectedTag)) {
        return BAD(`checkpoint ${cp.epochId}: the payload's domain tag is not this chain's ` +
                   "(a checkpoint signed for another chain or devnet cannot be reused here)");
      }
      const sig = hexBuf(cp.signature, `checkpoint ${cp.epochId} signature`);
      if (sig.length !== 64) return BAD(`checkpoint ${cp.epochId}: signature is not 64 bytes`);
      if (!crypto.verify(null, digest, key, sig)) {
        return BAD(`checkpoint ${cp.epochId}: the authority signature does not verify`);
      }
    }
    // The signatures and the chain-identity binding are now PROVED. On devnet the registry
    // additionally requires the height-one genesis block to be retrieved and authenticated.
    //
    // THE DUTY IS NOW PERFORMED, NOT PRESUMED (repository-access review round 4, MUST-FIX).
    // The previous version returned OK for ANY truthy coreNode, `{}` included, so an
    // attestation could be minted for a retrieval-and-validation duty nothing had performed,
    // and the positive fixture REQUIRED that wrong outcome. A verifier's ok:true must mean
    // the named checks ran. The Core node interface is one method,
    // `getBlockHexByHeight(height)` returning the raw block (or at least its 80-byte
    // header) as hex; a coreNode without it leaves the component BLOCKED, never completed.
    //
    // What is checked, and why each piece is needed (round 5, MUST-FIX: the previous version
    // checked an 80-byte HEADER only, called the name commitment "committed under the verified
    // hash", and validated nBits so loosely that nBits 0x2200ffff expanded to a target beyond
    // the 256-bit range, which every hash satisfies. Two of the registry's four named checks
    // were therefore not performed, and a fabricated header passed):
    //   FULL BLOCK   the coinbase is required, so a header alone is refused
    //   hash         dsha256(header), display order, equals network.coreDevnetGenesisBlockHash
    //   parent       header bytes 4..36, display order, equals network.coreGenesisBlockHash
    //   merkle root  header bytes 36..68 equals the coinbase txid. THIS is what actually binds
    //                the coinbase to the verified hash. Without it, "the name is committed
    //                under the hash" was an assertion about a block nothing had parsed.
    //   proof of work  consensus-equivalent bounds: mantissa nonzero, sign bit clear, the
    //                expanded target nonzero AND inside 256 bits, then hash <= target
    //   coinbase     one transaction, whose scriptSig pushes the BIP34 height 1 followed by a
    //                NONEMPTY devnet-name push, which is what
    //                8c9f166a3:src/chainparams.cpp:43-64 CreateDevNetGenesisBlock writes. The
    //                registry asks for a nonempty commitment rather than a match against a
    //                declared name, and the envelope carries no devnet-name field to match
    //                against, so nonempty is both what is required and what is checkable.
    const proved = `${env.checkpoints.length} checkpoint signature(s) verified under the fixed authority, ` +
      "and every payload's domain tag re-derived from this envelope's own chain identity";
    if (env.network.coreNetwork === "devnet") {
      if (!coreNode || typeof coreNode.getBlockHexByHeight !== "function") {
        return { ran: false, ok: false, proved,
                 blockedOn: "a Core node exposing getBlockHexByHeight, to retrieve and " +
                            "authenticate the devnet height-one genesis block" };
      }
      const blockHex = coreNode.getBlockHexByHeight(1);
      if (typeof blockHex !== "string" || !/^(?:[0-9a-f]{2})+$/.test(blockHex) || blockHex.length < 160) {
        return BAD("the Core node did not return a parseable height-one block");
      }
      const block = hexBuf(blockHex, "the height-one block");
      const header = block.subarray(0, 80);
      // A DASH BLOCK HASH IS X11, NOT SHA-256d. This computed sha256d and compared it to the
      // committed genesis, and its fixture MINED with sha256d too, so code and fixture agreed with
      // each other and both disagreed with Dash: no real devnet genesis block could ever have
      // satisfied this check. Transaction ids and merkle nodes really are sha256d, which is what
      // makes the block hash easy to get wrong.
      const display = blockHashOf(header);
      if (display !== env.network.coreDevnetGenesisBlockHash) {
        return BAD(`the retrieved height-one block hashes to ${display}, not the envelope's ` +
                   "coreDevnetGenesisBlockHash");
      }
      const parent = Buffer.from(header.subarray(4, 36)).reverse().toString("hex");
      if (parent !== env.network.coreGenesisBlockHash) {
        return BAD("the retrieved height-one block does not extend the envelope's height-zero genesis");
      }

      // ---- proof of work, with the bounds consensus actually applies ----
      // Round 6, MUST-FIX: this checked only that the expanded target was nonzero and below 2^256
      // and never applied the NETWORK LIMIT, so nBits 0x2100ffff, whose target sits above the
      // devnet limit and below 2^256, passed. CheckProofOfWork rejects on negative, zero, OVERFLOW
      // or target > powLimit before it compares the hash [8c9f166a3:src/pow.cpp:236-252], and the
      // limits are ~uint256(0)>>1 for devnet and regtest, ~uint256(0)>>20 for mainnet and testnet
      // [src/chainparams.cpp:198, 399, 574, 810].
      const POW_LIMIT = {
        mainnet: BigInt("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        testnet: BigInt("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        devnet: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        regtest: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
      };
      const powLimit = POW_LIMIT[env.network.coreNetwork];
      if (powLimit === undefined) {
        return BAD(`no proof-of-work limit is known for coreNetwork ${env.network.coreNetwork}`);
      }
      const nBits = header.readUInt32LE(72);
      // SetCompact, including the flags consensus reads back [src/arith_uint256.cpp]
      const exponent = nBits >>> 24;
      const mantissa = nBits & 0x007fffff;
      const negative = mantissa !== 0 && (nBits & 0x00800000) !== 0;
      const overflow = mantissa !== 0 && ((exponent > 34) ||
                                          (mantissa > 0xff && exponent > 33) ||
                                          (mantissa > 0xffff && exponent > 32));
      if (negative) return BAD("the height-one header carries a negative nBits target");
      if (overflow) return BAD(`the height-one header's nBits ${nBits.toString(16)} overflows`);
      const target = exponent <= 3
        ? BigInt(mantissa) >> (8n * BigInt(3 - exponent))
        : BigInt(mantissa) << (8n * BigInt(exponent - 3));
      if (target === 0n) return BAD("the height-one header carries a zero nBits target");
      if (target > powLimit) {
        return BAD(`the height-one header's target exceeds the ${env.network.coreNetwork} ` +
                   "proof-of-work limit");
      }
      // CheckProofOfWork compares the BLOCK hash against the target, so this is the X11 value too
      const blockHashInternal = Buffer.from(display, "hex").reverse();
      let hashInt = 0n;
      for (let i = blockHashInternal.length - 1; i >= 0; i--) {
        hashInt = (hashInt << 8n) | BigInt(blockHashInternal[i]);
      }
      if (hashInt > target) return BAD("the retrieved height-one block does not satisfy its own proof of work");

      // ---- the coinbase, bound to the verified hash by the merkle root ----
      const cb = readGenesisCoinbase(block);
      if (cb.error) return BAD(`the height-one block's coinbase ${cb.error}`);
      const merkleRoot = header.subarray(36, 68);
      if (!merkleRoot.equals(cb.txid)) {
        return BAD("the height-one header's merkle root is not the coinbase txid, so the " +
                   "coinbase is not committed under the verified hash");
      }
      if (!cb.nameCommitment || cb.nameCommitment.length === 0) {
        return BAD("the height-one coinbase carries no nonempty devnet-name commitment");
      }
      return OK(proved + "; the devnet height-one block was retrieved and authenticated " +
                `(hash, parent, proof of work, and a ${cb.nameCommitment.length}-byte devnet-name ` +
                "commitment in a coinbase bound by the header's merkle root)");
    }
    return OK(proved);
  } catch (e) {
    return BAD((e && e.message) || String(e));
  }
}


/**
 * verifyCoreWalk - the Core-side continuity and finality checks, RECOMPUTED from the retained
 * wire bytes rather than read off the record's own assertions.
 *
 * The duty is docs/CORE_WALK_DUTY_STATEMENT.md, which lists the registry's seven checks with the
 * input each consumes. This implements the ones whose evidence the record carries, and reports
 * the rest as outstanding instead of quietly counting them as done.
 *
 * WHAT IT RECOMPUTES, per listWalk row:
 *   the diff parses under the pinned codec at the negotiated protocol range;
 *   the diff's own blockHash equals the row's blockHash;
 *   the diff CONTINUES the previous row (its baseBlockHash is the previous row's blockHash, and
 *     the first row continues the base package's own block);
 *   the masternode-list ROOT recomputed from the diff's entries equals the commitment inside
 *     that block's coinbase, and equals the row's asserted listRoot. This is the check that makes
 *     listRoot evidence rather than a claim, and it is anchored to a value Dash Core wrote;
 *   the coinbase bytes the row retains are the SAME bytes the diff carries;
 *   where the coreLedger covers the same height, its blockHash agrees and its coinbase outputs
 *     are DERIVED from txRaw rather than trusted (a soundness review).
 * Plus the interval equation over already-validated integers.
 *
 * WHAT IT DOES NOT DO, and why the component stays blocked. The endpoint ChainLock signature must
 * be checked under quorum material DERIVED from the retained quorum commitments. The signature
 * layer exists and is verified against a real ChainLock (chainLockVerify.cjs), but it needs an
 * asynchronously loaded BLS instance while this harness is synchronous, and the derivation of
 * quorum material from `quorumDerivation` is not implemented. So this returns ran:false with what
 * it PROVED, exactly as the recognition verifier does for its own outstanding duty.
 *
 * ON PLACEHOLDER EVIDENCE. The offline suite's vectors carry placeholder blobs by design, which
 * the registry states for this very component. Such a record is REFUSED here, and that is the
 * correct answer rather than an inconvenience: a record whose retained bytes do not parse under
 * the pinned codec is not one this verifier can make any claim about.
 */
function verifyCoreWalk(env, { protocolVersion = 70240 } = {}) {
  const checks = {};
  const note = (name, passed, detail) => { checks[name] = { passed, detail }; return passed; };
  try {
    const walk = env.coverage && env.coverage.listWalk;
    if (!Array.isArray(walk) || walk.length === 0) return BAD("the record carries no list walk");

    // ---- check 5, the interval equation: integers already validated by the schema layer ----
    const observed = env.lifecycle && env.lifecycle.observedThroughHeight;
    const toHeight = env.coreAuditRange && env.coreAuditRange.toHeight;
    const clHeight = env.validatedChainLock && env.validatedChainLock.height;
    if (!Number.isSafeInteger(observed) || !Number.isSafeInteger(toHeight) || !Number.isSafeInteger(clHeight)) {
      return BAD("the coverage interval carries a non-integer height");
    }
    if (!note("coverageInterval", observed >= toHeight && observed <= clHeight,
              `observedThroughHeight ${observed} against toHeight ${toHeight} and chainlock ${clHeight}`)) {
      return BAD(`the coverage interval is unsatisfied: observedThroughHeight ${observed}, ` +
                 `toHeight ${toHeight}, chainlock ${clHeight}`);
    }

    // ---- checks 1, 2, 6 and 7, per row, over the retained wire bytes ----
    const ledgerByHeight = new Map();
    for (const row of (env.coverage.coreLedger || [])) ledgerByHeight.set(row.height, row);

    // ---- THE RETAINED HEADER CHAIN, indexed by block hash (round 6, MAJOR) ----
    // The walk needs the header to authenticate anything: the coinbase is bound to a block by the
    // header's merkle root, and nothing else in the record can supply it.
    let headersByHash;
    try {
      headersByHash = indexHeaderChain(env.coreHeaderChain);
    } catch (e) {
      return BAD(`the retained coreHeaderChain does not parse (${(e && e.message) || e})`);
    }

    // ---- SEED THE LIST AT THE BASE (round 6, MAJOR: there was no list state at all) ----
    // A diff is a DELTA, so a root can only be derived by transforming the previous list. Where
    // the base list comes from is answered by the format, not chosen here
    // (docs/CORE_WALK_DUTY_STATEMENT.md): a rooted base retains every entry in
    // basePackage.smlEntries[], and a pre-DML base retains none because before deterministic
    // lists activated there is no list.
    const bp = env.basePackage || {};
    let listState;
    if (bp.kind === "pre-dml") {
      listState = [];
      note("baseListSeeded", true, "pre-DML base: the list at the base block is empty");
    } else if (bp.kind === "rooted") {
      if (!Array.isArray(bp.smlEntries)) {
        return BAD("a rooted base package retains no smlEntries array to seed the list from");
      }
      try {
        listState = bp.smlEntries.map((hex, i) => parseStandaloneEntry(
          hexBuf(hex, `basePackage.smlEntries[${i}]`), { protocolVersion }));
      } catch (e) {
        return BAD(`a base list entry does not parse under dash-smlentry-serialization-v1 ` +
                   `(${(e && e.message) || e})`);
      }
      note("baseListSeeded", true, `${listState.length} entry(ies) parsed from the rooted base`);
    } else {
      return BAD(`the base package names an unknown kind ${JSON.stringify(bp.kind)}`);
    }
    let previousBlockHash = env.basePackage && env.basePackage.baseBlock &&
                            env.basePackage.baseBlock.blockHash;
    let rootsChecked = 0;
    let coinbasesAuthenticated = 0;
    let outputsChecked = 0;

    for (const row of walk) {
      const where = `list-walk row at height ${row.height}`;
      let diff;
      try {
        diff = parseMnListDiff(hexBuf(row.protxDiffRaw, `${where} protxDiffRaw`), { protocolVersion });
      } catch (e) {
        return BAD(`${where}: protxDiffRaw does not parse under dash-p2p-mnlistdiff-v1 ` +
                   `(${(e && e.message) || e})`);
      }
      if (diff.blockHash !== row.blockHash) {
        return BAD(`${where}: the diff describes block ${diff.blockHash}, not the row's ${row.blockHash}`);
      }
      if (previousBlockHash && diff.baseBlockHash !== previousBlockHash) {
        return BAD(`${where}: the diff continues ${diff.baseBlockHash}, breaking the chain from ` +
                   `${previousBlockHash}`);
      }
      previousBlockHash = row.blockHash;

      // the retained coinbase must be the SAME bytes the diff carries
      if (row.cbTxRaw !== diff.cbTx.raw) {
        return BAD(`${where}: the retained cbTxRaw is not the coinbase the diff carries`);
      }
      // APPLY THE DELTA, then take the root over the RESULTING list. Computing it over
      // diff.mnList is the root of the CHANGES, which is what round 6 caught: a row carrying two
      // of three entries as its delta produced a root matching nothing, and a full list relabelled
      // as a diff from another base passed, because no base list was ever read.
      try {
        listState = applyDiffToList(listState, diff);
      } catch (e) {
        return BAD(`${where}: the diff does not apply to the list at the previous height ` +
                   `(${(e && e.message) || e})`);
      }
      // ---- AUTHENTICATE THE COINBASE BEFORE BELIEVING ITS PAYLOAD (round 6, MAJOR) ----
      // Previously the coinbase was read out of the diff and its payload treated as a value Dash
      // Core committed, with cbTxMerkleTree and the row's cbTxInclusionProof both unused. Flipping
      // one byte of the tree left every check passing. The binding is: the header retained for this
      // block must hash to the row's blockHash, the root extracted from the diff's partial merkle
      // tree must equal that header's merkle root, and the coinbase txid must be among the txids
      // the tree proves. Only then is its payload evidence rather than an assertion.
      const header = headersByHash.get(row.blockHash);
      if (!header) {
        return BAD(`${where}: the retained header chain holds no header hashing to ${row.blockHash}`);
      }
      let proof;
      try {
        proof = extractMerkleMatches(diff.cbTxMerkleTree);
      } catch (e) {
        return BAD(`${where}: the diff's cbTxMerkleTree is malformed (${(e && e.message) || e})`);
      }
      if (proof.merkleRoot !== header.merkleRoot) {
        return BAD(`${where}: the coinbase proof yields merkle root ${proof.merkleRoot}, but the ` +
                   `block's header commits ${header.merkleRoot}`);
      }
      if (!proof.matched.includes(diff.cbTx.txid)) {
        return BAD(`${where}: the coinbase ${diff.cbTx.txid} is not among the transactions its own ` +
                   "proof establishes, so it is not bound to this block");
      }
      coinbasesAuthenticated++;

      // THE LIST ROOT, against the coinbase's own commitment AND the row's assertion
      const payload = readCbTxPayload(diff.cbTx);
      const root = computeListRoot(listState);
      if (root !== payload.merkleRootMNList) {
        return BAD(`${where}: the recomputed list root ${root} does not match the coinbase ` +
                   `commitment ${payload.merkleRootMNList}`);
      }
      if (row.listRoot !== root) {
        return BAD(`${where}: the asserted listRoot ${row.listRoot} is not the recomputed ${root}`);
      }
      rootsChecked++;

      // check 6 and 7 where the Core ledger covers the same height
      const ledgerRow = ledgerByHeight.get(row.height);
      if (ledgerRow) {
        if (ledgerRow.blockHash !== row.blockHash) {
          return BAD(`${where}: the Core ledger names a different block at the same height`);
        }
        const cb = ledgerRow.coinbase;
        if (cb && cb.kind === "available") {
          if (cb.txRaw !== row.cbTxRaw) {
            return BAD(`${where}: the Core ledger's coinbase bytes differ from the walk's`);
          }
          const derived = diff.cbTx.vout.map((o) => ({
            script: o.script, amountDuffs: o.valueDuffs, outputIndex: o.index,
          }));
          const asserted = (cb.outputs || []).map((o) => ({
            script: o.script, amountDuffs: o.amountDuffs, outputIndex: o.outputIndex,
          }));
          if (JSON.stringify(derived) !== JSON.stringify(asserted)) {
            // no internal finding tag in a RUNTIME MESSAGE. This read "(a soundness review)", and the fixture
            // matched on that tag, so the two were coupled through a private tracking number.
            // The public export genericizes such tags, and it rewrites a parenthesized tag and a
            // bare one differently, so the message and the fixture's pattern drifted apart and
            // the published suite failed a check that passes here. A refusal names its RULE.
            return BAD(`${where}: the serialized coinbase outputs are not what txRaw parses to`);
          }
          outputsChecked++;
        }
      }
    }
    note("diffChainContinuity", true, `${walk.length} row(s) chained without gap or reordering`);
    note("listRootPerHeight", true,
       `${rootsChecked} root(s) recomputed over the RESULTING list after applying each delta, ` +
       `each matching the coinbase commitment; the list ends with ${listState.length} entry(ies)`);
    note("coinbaseOutputsDerived", true, `${outputsChecked} coinbase output array(s) derived from txRaw`);
    note("oneChainTwoLedgers", true, "shared heights agree on block hash and coinbase bytes");
    note("coinbaseAuthenticated", true,
         `${coinbasesAuthenticated} coinbase(s) proven into their block by the retained header's ` +
         "merkle root, so the commitment each carries is evidence rather than an assertion");

    const proved = `${walk.length} walk row(s): diffs parse under the pinned codec, chain without ` +
      `gap, every coinbase is proven into its block by the retained header's merkle root ` +
      `(${coinbasesAuthenticated}), and every recomputed list root matches the commitment that ` +
      `authenticated coinbase carries (${rootsChecked}); ${outputsChecked} coinbase output ` +
      "array(s) derived from txRaw";
    // The endpoint ChainLock check is the outstanding duty. It is NOT counted as done.
    return {
      ran: false, ok: false, proved, checks,
      blockedOn: "the endpoint ChainLock signature check under quorum material DERIVED from the " +
                 "retained quorum commitments: the signature layer needs an asynchronously loaded " +
                 "BLS instance while this harness is synchronous, and quorumDerivation is not yet " +
                 "interpreted. The header-chain ANCESTRY check is also outstanding: headers are " +
                 "indexed and each row's header is required to hash to its block, but nothing yet " +
                 "proves the chain of parents reaches the endpoint.",
    };
  } catch (e) {
    return BAD((e && e.message) || String(e));
  }
}

// ---------------------------------------------------------------------------
// DECLARED BUT BLOCKED (never silently absent)
// ---------------------------------------------------------------------------

const BLOCKED_VERIFIERS = {
  // The sign-hash CONSTRUCTION is now established from source and a REAL ChainLock plus
  // its live quorum set is pinned at fixtures/chainlock-devnet-2026-07-25.json, so the
  // next attempt starts from data. What is still unknown is the exact Dash BLS scheme:
  // naive IETF-basic verification (noble bls12-381, NUL DST) over that construction did
  // NOT verify across 112 byte-order and llmqType combinations, which points at Dash's
  // legacy hash-to-curve or the signing-quorum selection rule rather than the sign hash.
  // Shipping an unvalidated signature verifier would be worse than shipping none.
  verifyBasePackage: "the SML root computation over a pinned real capture; the BLS ChainLock half is implemented in chainLockVerify.cjs and verified against real data",
  verifyPlatformCommits: "the real Tenderdash protobuf header, commit and proof codecs (the proof-verifier bundle the envelope commits by digest)",
  verifyDecodeDispositions: "the decoder bundle artifact itself (a build output that does not exist yet)",
  verifyBookConformance: "retrieved, authenticated pool-document state and the contract-creation transition",
  verifyConservation: "the owner-payout derivation from the masternode's L1 state (scriptPayout + share table)",
  verifyL1BackingAtHeight: "structurally barred in v1: the component has an empty evidence set by design",
  verifyReceiptDuties: "structurally barred in v1: the component has an empty evidence set by design",
};

const IMPLEMENTED = {
  verifyIdentifierConversion,
  verifyTransitionHashes,
  verifyCheckpointRecognition,
  // verifyCoreWalk performs several of its named checks and reports the rest as outstanding, so
  // it lives here rather than among the declared-blocked stubs. It still cannot return ok:true,
  // because the endpoint ChainLock check has not run; what changed is that its result now carries
  // what it actually PROVED instead of only naming a dependency.
  verifyCoreWalk,
};

/** every verifier the registry names, implemented or declared-blocked */
function allVerifiers() {
  const out = { ...IMPLEMENTED };
  for (const [name, blockedOn] of Object.entries(BLOCKED_VERIFIERS)) {
    out[name] = () => BLOCKED(blockedOn);
  }
  return out;
}

const COMPONENT_OF = {
  verifyCheckpointRecognition: "recognition",
  verifyBasePackage: "baseProof",
  verifyCoreWalk: "coreContinuityFinality",
  verifyPlatformCommits: "platformCommits",
  verifyDecodeDispositions: "decoderCoverage",
  verifyL1BackingAtHeight: "l1Backing",
  verifyReceiptDuties: "receiptValidity",
  verifyBookConformance: "bookConformance",
  verifyConservation: "conservation",
  verifyTransitionHashes: "transitionHashing",
  verifyIdentifierConversion: "identifierConversion",
};

/**
 * runVerifiers - execute every verifier over an envelope's evidence and return both the
 * per-verifier results and the ATTESTATIONS the writer accepts.
 *
 * An attestation is produced ONLY for a verifier that ran AND succeeded, and it carries
 * the digest of the evidence it ran over, so it cannot be recycled onto other evidence.
 * `evidence` must be the SAME object the writer will serialize.
 */
function runVerifiers(evidence, context = {}) {
  const evidenceDigest = crypto.createHash("sha256").update(canonicalize(evidence)).digest("hex");
  const verifiers = allVerifiers();
  const results = {};
  const attestations = [];
  for (const [name, fn] of Object.entries(verifiers)) {
    const component = COMPONENT_OF[name];
    let r;
    try {
      r = fn(evidence, context);
    } catch (e) {
      r = BAD(`the verifier threw: ${(e && e.message) || e}`);
    }
    results[name] = { component, ...r };
    if (r.ran === true && r.ok === true) {
      attestations.push({ component, verifier: name, ran: true, ok: true, evidenceDigest });
    }
  }
  return { evidenceDigest, results, attestations };
}

module.exports = {
  coreChainIdentityHash, v2DomainTag,
  verifyIdentifierConversion, verifyTransitionHashes, verifyCheckpointRecognition, verifyCoreWalk,
  allVerifiers, runVerifiers, BLOCKED_VERIFIERS, COMPONENT_OF,
};
