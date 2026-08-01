/**
 * Fixtures for the P2P mnlistdiff parser, driven entirely by the REAL captured wire bytes
 * (fixtures/p2p-mnlistdiff-regtest-2026-07-27.json, 3645 bytes at protocol 70240).
 *
 * The decisive check is the LIST ROOT. The parser recomputes the masternode-list root from the
 * bytes it parsed and it must equal the commitment inside the block's own coinbase. That is a
 * property no amount of self-consistency can fake: the commitment was written by Dash Core, and
 * reproducing it requires the entry serialization, the hash preimage, the sort order and the tree
 * construction to ALL be right. It is also registry verifierCheck 2, the check the eligibility
 * claim rests on.
 *
 * The second discipline here is the ORACLE. Every parsed field is compared against the same
 * node's `protx diff` output over the same block range, captured alongside the wire bytes. A
 * parser validated only against itself is what produced a soundness-review finding.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const {
  parseMnListDiff, computeListRoot, readCbTxPayload, PROTO,
} = require("./mnListDiffCodec.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const eq = (name, a, b) => {
  if (JSON.stringify(a) === JSON.stringify(b)) { pass++; } else {
    fail++; console.error(`FAIL: ${name}\n  ours ${JSON.stringify(a)}\n  node ${JSON.stringify(b)}`);
  }
};
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const FIX = path.join(__dirname, "fixtures", "p2p-mnlistdiff-regtest-2026-07-27.json");
const fx = JSON.parse(fs.readFileSync(FIX, "utf8"));
const raw = Buffer.from(fx.payloadHex, "hex");
const diff = parseMnListDiff(raw, { protocolVersion: fx.protocolVersionOffered });

// ---- THE LIST ROOT, against the coinbase's own commitment ----
{
  const cb = readCbTxPayload(diff.cbTx);
  ok("the coinbase payload is a version-3 CbTx carrying a height", cb.version === 3 && cb.height > 0);
  const root = computeListRoot(diff.mnList);
  ok("THE LIST ROOT REPRODUCES THE COINBASE COMMITMENT", root === cb.merkleRootMNList);
  ok("the root is not accidentally the empty-tree value",
     root !== Buffer.alloc(32).toString("hex"));

  // the two rules that had to be right, each asserted so a regression names itself
  const wireOrder = diff.mnList.map((e) => e.proRegTxHash);
  const displayOrder = wireOrder.slice().sort();
  const internalOrder = diff.mnList.slice()
    .sort((a, b) => Buffer.compare(Buffer.from(a.proRegTxHash, "hex").reverse(),
                                   Buffer.from(b.proRegTxHash, "hex").reverse()))
    .map((e) => e.proRegTxHash);
  ok("the sort that reproduces the root is NOT display-hex order (they differ on this capture)",
     JSON.stringify(displayOrder) !== JSON.stringify(internalOrder));
  ok("each entry's hash preimage OMITS the wire-only nVersion",
     diff.mnList.every((e) => e.hashPreimage.length === e.raw.length - 2));
}

// ---- ORACLE AGREEMENT: every parsed field against the node's own answer ----
{
  const o = fx.rpcOracle.diff;
  eq("nVersion matches the node", diff.nVersion, o.nVersion);
  eq("baseBlockHash matches the node", diff.baseBlockHash, o.baseBlockHash);
  eq("blockHash matches the node", diff.blockHash, o.blockHash);
  eq("the coinbase bytes match the node", diff.cbTx.raw, o.cbTx);
  eq("deletedMNs matches the node", diff.deletedMNs, o.deletedMNs);
  eq("the entry count matches the node", diff.mnList.length, o.mnList.length);

  const byHash = Object.fromEntries(o.mnList.map((e) => [e.proRegTxHash, e]));
  for (const e of diff.mnList) {
    const r = byHash[e.proRegTxHash];
    ok(`the node also lists ${e.proRegTxHash.slice(0, 8)}`, Boolean(r));
    if (!r) continue;
    for (const f of ["nVersion", "nType", "confirmedHash", "pubKeyOperator", "isValid",
                     "platformNodeID", "platformHTTPPort"]) {
      eq(`${f} of ${e.proRegTxHash.slice(0, 8)}`, e[f], r[f]);
    }
    eq(`service of ${e.proRegTxHash.slice(0, 8)}`, e.netInfo.service, r.service);
  }
}

// ---- the frame itself ----
{
  // This pair used to assert that the quorum sections were NOT decoded, which was true of the
  // previous increment and is now false. It is replaced rather than deleted, because the property
  // that mattered is still worth holding: the parser must never report success over a partial read.
  ok("the parse reaches the end of the payload", diff.bytesConsumed === raw.length);
  eq("no member is left undecoded now that the quorum sections are read", diff.undecoded, []);
  ok("every entry records the exact bytes it was parsed from",
     diff.mnList.every((e) => Buffer.isBuffer(e.raw) && e.raw.length === 177));
  ok("the entry slices are contiguous and reassemble the list region", (() => {
    const joined = Buffer.concat(diff.mnList.map((e) => e.raw));
    return raw.includes(joined);
  })());
}

// ---- refusals: the module must decline rather than guess ----
{
  throws("a protocol below the supported range is refused",
    () => parseMnListDiff(raw, { protocolVersion: PROTO.MNLISTDIFF_VERSION_ORDER }),
    /outside the supported range/);
  throws("a protocol above the supported range is refused",
    () => parseMnListDiff(raw, { protocolVersion: PROTO.CURRENT + 1 }),
    /outside the supported range/);
  throws("a missing protocol version is refused, since the layout depends on it",
    () => parseMnListDiff(raw, {}), /protocolVersion is required/);
  throws("a truncated payload is refused by name, never parsed short",
    () => parseMnListDiff(raw.subarray(0, 200), { protocolVersion: 70240 }),
    /needs \d+ bytes at offset/);
  throws("a non-buffer payload is refused", () => parseMnListDiff("aabb", { protocolVersion: 70240 }),
    /must be a Buffer/);
}

// ---- THE QUORUM SECTIONS ----
{
  const o = fx.rpcOracle.diff;

  // The acid test for a frame parser: every byte accounted for. parseMnListDiff refuses if any
  // remain, so reaching here at all means the three quorum sections were read to the end.
  ok("the parse consumed the payload exactly, with nothing left over",
     diff.bytesConsumed === raw.length && diff.bytesRemaining === 0);
  eq("nothing is left undecoded", diff.undecoded, []);

  eq("the deletedQuorums list matches the node", diff.deletedQuorums.length, o.deletedQuorums.length);
  eq("the newQuorums count matches the node", diff.newQuorums.length, o.newQuorums.length);
  ok("the capture carries the chainlock-signature section the protocol adds at 70230",
     Array.isArray(diff.quorumsCLSigs) && diff.quorumsCLSigs.length > 0);

  const key = (q) => `${q.llmqType}|${q.quorumHash}`;
  const byKey = Object.fromEntries(o.newQuorums.map((q) => [key(q), q]));
  for (const q of diff.newQuorums) {
    const r = byKey[key(q)];
    ok(`the node also reports quorum ${q.quorumHash.slice(0, 8)}`, Boolean(r));
    if (!r) continue;
    eq(`commitment version of ${q.quorumHash.slice(0, 8)}`, q.nVersion, r.version);
    eq(`quorumPublicKey of ${q.quorumHash.slice(0, 8)}`, q.quorumPublicKey, r.quorumPublicKey);
    eq(`quorumVvecHash of ${q.quorumHash.slice(0, 8)}`, q.quorumVvecHash, r.quorumVvecHash);
    eq(`quorumSig of ${q.quorumHash.slice(0, 8)}`, q.quorumSig, r.quorumSig);
    eq(`membersSig of ${q.quorumHash.slice(0, 8)}`, q.membersSig, r.membersSig);
    // the bitsets are the fiddly part: the count on the wire is in BITS, not bytes
    eq(`signers bitset of ${q.quorumHash.slice(0, 8)}`, q.signers.bytes, r.signers);
    eq(`validMembers bitset of ${q.quorumHash.slice(0, 8)}`, q.validMembers.bytes, r.validMembers);
    eq(`signersCount of ${q.quorumHash.slice(0, 8)}`, q.signers.setCount, r.signersCount);
    eq(`validMembersCount of ${q.quorumHash.slice(0, 8)}`, q.validMembers.setCount, r.validMembersCount);
  }

  // quorumIndex is on the wire ONLY for the indexed commitment versions. This capture carries
  // version 3, which is basic and NON-indexed, so the field is correctly absent from our parse
  // even though the node's JSON renders one.
  ok("this capture's commitments are the non-indexed version",
     diff.newQuorums.every((q) => q.nVersion === 3));
  ok("quorumIndex is absent from a non-indexed commitment, as the wire has it",
     diff.newQuorums.every((q) => q.quorumIndex === undefined));
  ok("the BLS scheme is derived from the commitment version",
     diff.newQuorums.every((q) => q.blsScheme === "basic"));
}

// WHAT THE QUORUM PARSE IS *NOT* VALIDATED BY, stated so nobody assumes otherwise. The coinbase
// also commits a merkleRootQuorums, and unlike merkleRootMNList it is NOT derivable from this
// payload: CalcCbTxMerkleRootQuorums works over the mined-and-active commitments up to the block
// plus chain parameters (which llmq types exist, whether rotation is enabled), none of which the
// diff carries [8c9f166a3:src/evo/cbtx.cpp:117-160]. So the quorum sections rest on exact byte
// consumption and oracle agreement, and there is no consensus commitment behind them the way
// there is for the masternode list.
{
  const cb = readCbTxPayload(diff.cbTx);
  ok("the coinbase does carry a quorum root, which this module deliberately does not claim to derive",
     typeof cb.merkleRootQuorums === "string" && cb.merkleRootQuorums.length === 64);
}

// ---------------------------------------------------------------------------
// ROUND 6 MAJOR: the parser accepted NON-CANONICAL CompactSize and checked no size ceiling, so
// consuming every byte did not mean the encoding was one Dash would accept. Both rules are the
// ones in src/serialize.h:288-317, and both are applied to the SAME helper every count in the
// frame, the transaction, the bitsets and the quorum sections goes through.
// ---------------------------------------------------------------------------
{
  const at = raw.indexOf(diff.mnList[0].raw);   // the masternode count sits immediately before
  const widen = (bytes) => Buffer.concat([raw.subarray(0, at - 1), Buffer.from(bytes), raw.subarray(at)]);

  throws("a two-byte form for a value that fits one byte is refused",
    () => parseMnListDiff(widen([0xfd, 0x03, 0x00]), { protocolVersion: 70240 }),
    /non-canonical CompactSize \(3 fits one byte\)/);
  throws("a four-byte form for a small value is refused",
    () => parseMnListDiff(widen([0xfe, 0x03, 0x00, 0x00, 0x00]), { protocolVersion: 70240 }),
    /non-canonical CompactSize \(3 fits two bytes\)/);
  throws("an eight-byte form for a small value is refused",
    () => parseMnListDiff(widen([0xff, 3, 0, 0, 0, 0, 0, 0, 0]), { protocolVersion: 70240 }),
    /non-canonical CompactSize \(3 fits four bytes\)/);
  // the boundary values themselves are LEGAL in their own width and must not be refused
  {
    const r = new (require("./mnListDiffCodec.cjs").Reader)(Buffer.from([0xfd, 0xfd, 0x00]));
    ok("253 in the two-byte form is accepted, since one byte cannot hold it", r.varint("t") === 253);
  }
  {
    const r = new (require("./mnListDiffCodec.cjs").Reader)(Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00]));
    ok("65536 in the four-byte form is accepted", r.varint("t") === 0x10000);
  }
  // and the MAX_SIZE ceiling, which nothing checked at all
  {
    const r = new (require("./mnListDiffCodec.cjs").Reader)(Buffer.from([0xfe, 0x00, 0x00, 0x00, 0x03]));
    let threw = null;
    try { r.varint("a count"); } catch (e) { threw = e.message; }
    ok("a count above MAX_SIZE is refused", threw !== null && /MAX_SIZE limit/.test(threw));
  }
  ok("the real capture still parses under the stricter rules",
     parseMnListDiff(raw, { protocolVersion: 70240 }).mnList.length === 3);
}

// the capture now records the COMMON protocol version, which is what selects the wire layout
{
  ok("the capture records the peer's offer and the common version, not only ours",
     fx.protocolVersionCommon === Math.min(fx.protocolVersionOffered, fx.protocolVersionPeerOffered));
  ok("parsing uses the common version", (() => {
    const d = parseMnListDiff(raw, { protocolVersion: fx.protocolVersionCommon });
    return d.mnList.length === 3 && d.bytesRemaining === 0;
  })());
}

// ---------------------------------------------------------------------------
// ROUND 7, from a review run that was cut off by its provider's filter after naming two candidate
// gaps. Both reproduced, so the leads were worth more than the missing report.
// ---------------------------------------------------------------------------
{
  const { indexHeaderChain, extractMerkleMatches } = require("./mnListDiffCodec.cjs");
  const header = fx.blockHeaderRaw;
  // `dash-header-chain-v1` is a u32 little-endian COUNT followed by that many 80-byte headers
  // (round 11, a soundness-review finding). These used to pass the bare header, which is not the codec's shape.
  const chainOf = (...headers) => {
    const n = Buffer.alloc(4);
    n.writeUInt32LE(headers.length, 0);
    return n.toString("hex") + headers.join("");
  };

  // (1) STRICT HEX ON THE RETAINED HEADER CHAIN. Buffer.from truncates at the first non-hex
  // character, and the truncated length is still a multiple of 80, so the length check could not
  // catch it: one real header followed by "zz" indexed one header and discarded the rest silently.
  throws("a header chain with a malformed tail is refused, not truncated",
    () => indexHeaderChain(chainOf(header) + "zz"), /even-length lowercase hex/);
  throws("an odd-length header chain is refused",
    () => indexHeaderChain(chainOf(header) + "0"), /even-length lowercase hex/);
  throws("upper-case hex is refused, since the domain is lower-case",
    () => indexHeaderChain(chainOf(header).toUpperCase()), /even-length lowercase hex/);
  ok("the real retained header still indexes to its block",
     indexHeaderChain(chainOf(header)).has(fx.blockHash));

  // THE COUNT PREFIX IS PART OF THE CODEC AND PART OF THE EVIDENCE (round 11, MAJOR, a soundness-review finding).
  // `dash-header-chain-v1` is a u32 little-endian count followed by that many 80-byte headers.
  // The reader used to start at byte zero, so it DECLINED every conforming chain (84 bytes for one
  // header does not divide by 80) and ACCEPTED unprefixed bytes that are outside the codec. The
  // two domains do not overlap, which is why nothing caught it until the profile was compared with
  // the reader.
  throws("an unprefixed chain, the shape the reader used to require, is now refused",
    () => indexHeaderChain(header), /whole number of 80-byte/);
  throws("a chain shorter than its count prefix is refused",
    () => indexHeaderChain("0100"), /needs its 4-byte count prefix/);
  throws("a chain with a prefix and no headers is refused",
    () => indexHeaderChain("00000000"), /carries no headers/);
  // the count is compared with what follows, so a prefix cannot describe a different chain
  throws("a count larger than the headers supplied is refused",
    () => indexHeaderChain(chainOf(header).replace(/^01000000/, "02000000")),
    /declares 2 header\(s\) and carries 1/);
  throws("a count smaller than the headers supplied is refused",
    () => indexHeaderChain(chainOf(header, header).replace(/^02000000/, "01000000")),
    /declares 1 header\(s\) and carries 2/);
  ok("a conforming two-header chain indexes both",
     indexHeaderChain(chainOf(header, header)).size === 1);   // same header twice, one hash
  ok("every refusal names the pinned codec, as the other codec refusals do", (() => {
    try { indexHeaderChain(header); return false; }
    catch (e) { return /dash-header-chain-v1/.test(e.message); }
  })());

  // (2) THE TRANSACTION-COUNT BOUND on a partial merkle tree. A count above what a maximum-size
  // block could hold describes a block that cannot exist, and without the bound such a tree was
  // ACCEPTED and returned a root.
  throws("a transaction count above the block-size bound is refused",
    () => extractMerkleMatches({ nTransactions: 0xffffffff, hashes: ["aa".repeat(32)], bits: "01" }),
    /above the \d+ a block of the maximum size could hold/);
  throws("a count just past the bound is refused",
    () => extractMerkleMatches({ nTransactions: Math.floor(2000000 / 60) + 1,
                                 hashes: ["aa".repeat(32)], bits: "01" }),
    /above the \d+/);
  ok("a count AT the bound is still allowed, so the rule refuses only the impossible", (() => {
    try {
      extractMerkleMatches({ nTransactions: Math.floor(2000000 / 60),
                             hashes: ["aa".repeat(32)], bits: "01" });
      return true;                     // it may fail later on bits/hashes, but not on the bound
    } catch (e) { return !/could hold/.test(e.message); }
  })());
  ok("the real tree still extracts its single transaction",
     extractMerkleMatches(diff.cbTxMerkleTree).matched.length === 1);

  // (3) THE TWO REFUSALS NO INPUT HAD EVER REACHED (round 7, MINOR, closed 2026-07-30). Both
  // checks were present and neither was guarded: the real tree holds ONE transaction, so it
  // extracts a single match and never descends to an internal node, and the oversized-count
  // cases above stop at the count bound. Removing either check therefore left the whole suite
  // green. These drive the function DIRECTLY with the smallest tree that reaches each branch,
  // which is why they work where the round-7 attempt through a spliced envelope did not.
  //
  // The identical-branch case needs two transactions, so the tree is one level deep and the
  // root is an internal node with both children present. Bits are read least-significant-first
  // within each byte, so 0x07 is [1,1,1]: the root is a parent of a match, then each leaf is
  // taken from the hash array. Giving both leaves the SAME hash is the condition Dash refuses,
  // because two distinct transactions cannot share a txid, and a tree that repeats a branch can
  // otherwise be used to claim a root for transactions that are not there.
  const H = (b) => b.repeat(32);
  throws("a tree whose two branches are identical is refused",
    () => extractMerkleMatches({ nTransactions: 2, hashes: [H("aa"), H("aa")], bits: "07" }),
    /repeats a branch/);
  // the control that makes the case above meaningful: the SAME shape with distinct leaves is
  // accepted, so the refusal is about the repetition and not about two-transaction trees
  ok("the same two-leaf shape with distinct branches is accepted", (() => {
    const r = extractMerkleMatches({ nTransactions: 2, hashes: [H("aa"), H("bb")], bits: "07" });
    return r.matched.length === 2 && typeof r.merkleRoot === "string";
  })());

  // a tree covering no transactions has no root to extract; without this the width arithmetic
  // below it runs on an empty tree
  throws("a tree covering zero transactions is refused",
    () => extractMerkleMatches({ nTransactions: 0, hashes: [], bits: "00" }),
    /covers no transactions/);
}

// ---------------------------------------------------------------------------
// THE MISSING-DELETE REFUSAL, driven directly (round 7, MINOR, closed 2026-07-30).
//
// The suite's delta case was labelled as exercising a deletion of a missing entry, but the
// spliced payload it used inherited the capture's EMPTY deletedMNs, so the loop that raises this
// error never ran and the case failed later on a root mismatch instead. Removing the check left
// it green. applyDiffToList is exported and pure, so the honest way to guard the branch is to
// hand it a diff that actually deletes something absent.
//
// It matters because the deletion set is how a diff shrinks the list. A diff that deletes an
// entry the previous height does not hold is describing a different chain of lists than the one
// being walked, and silently ignoring it would let the recomputed root be taken over a list the
// evidence never supports.
// ---------------------------------------------------------------------------
{
  const { applyDiffToList } = require("./mnListDiffCodec.cjs");
  const entry = (h) => ({ proRegTxHash: h });
  const A = "11".repeat(32), B = "22".repeat(32);

  throws("deleting an entry the previous list does not hold is refused",
    () => applyDiffToList([entry(A)], { mnList: [], deletedMNs: [B] }),
    /deletes 2{64}, which the list at the previous height does not hold/);
  throws("deleting from an EMPTY previous list is refused",
    () => applyDiffToList([], { mnList: [], deletedMNs: [A] }),
    /does not hold/);
  // the control: deleting an entry that IS present works, so the rule refuses only the absent one
  ok("deleting an entry the list holds removes it",
     applyDiffToList([entry(A), entry(B)], { mnList: [], deletedMNs: [A] })
       .map((e) => e.proRegTxHash).join() === B);
  // and the delete is applied BEFORE the additions, so a diff may delete an entry and re-add it
  ok("a delete followed by a re-add in the same diff yields the added entry",
     applyDiffToList([entry(A)], { mnList: [entry(A)], deletedMNs: [A] })
       .map((e) => e.proRegTxHash).join() === A);
}

// ---------------------------------------------------------------------------
// TWO DECODER REFUSALS THAT EXISTED WITHOUT A FIXTURE (round 8, finding 4, closed 2026-07-30).
// Both were implemented and neither was driven: the supported-range and short-read branches had
// focused cases, these two did not, and the positive exact-consumption assertion does not guard
// the trailing-byte refusal because a valid capture leaves nothing over either way. Removing
// either check left the suite green.
// ---------------------------------------------------------------------------
{
  const { parseStandaloneEntry } = require("./mnListDiffCodec.cjs");
  const pv = fx.protocolVersionOffered;

  // The extended address entry form. No capture exercises it, so the decoder declines by name
  // rather than inventing a layout, and that decision is the thing worth guarding: a parser that
  // quietly guessed the ExtNetInfo layout would produce entries nothing validates.
  const extEntry = Buffer.concat([Buffer.from("0300", "hex"), Buffer.alloc(64)]);
  throws("an entry declaring the extended address form is refused by name",
    () => parseStandaloneEntry(extEntry, { protocolVersion: pv }),
    /extended address form/);
  // the control: the same shape at a version the decoder DOES handle gets past the version gate,
  // so the refusal is about the form and not about short synthetic entries
  ok("a non-ExtAddr entry version gets past the version gate", (() => {
    try {
      parseStandaloneEntry(Buffer.concat([Buffer.from("0200", "hex"), Buffer.alloc(64)]),
                           { protocolVersion: pv });
      return true;
    } catch (e) { return !/extended address form/.test(e.message); }
  })());

  // Trailing bytes. A parser that stops early and reports success lets a caller believe it
  // verified a section nobody read, so the whole payload must be consumed.
  throws("a valid payload followed by one extra byte is refused",
    () => parseMnListDiff(Buffer.concat([raw, Buffer.from([0])]), { protocolVersion: pv }),
    /bytes remain after the frame/);
  ok("the untouched payload still consumes exactly",
     parseMnListDiff(raw, { protocolVersion: pv }).bytesRemaining === 0);
}

console.log(`mnListDiffCodecTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
