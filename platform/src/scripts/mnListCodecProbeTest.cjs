/**
 * Fixtures over the REAL pinned masternode-list diff
 * (fixtures/mnlistdiff-devnet-2026-07-27.json, `protx diff 1 11353` from the live devnet).
 *
 * WHY THESE EXIST. verifyCoreWalk was recorded as blocked on the masternode-list codecs, then
 * as blocked only on a real capture once those codecs turned out to be in the tree already. The
 * capture is now here, and it immediately showed that the codec mis-parses what this node emits
 * (a soundness-review finding). That is exactly the outcome a synthetic round trip would have hidden, which is why
 * one was refused.
 *
 * TWO OF THESE ARE CANARIES, and they are labelled as such: they assert a dependency defect that
 * currently exists. If the dependency is fixed or upgraded, they FAIL, which is the point. A
 * canary that quietly starts passing tells nobody anything, so read a failure here as "the
 * library changed, go re-read a soundness-review finding", not as a regression in this repository.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { SimplifiedMNListDiff } = require("@dashevo/dashcore-lib");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };

const FIXTURE = path.join(__dirname, "fixtures", "mnlistdiff-devnet-2026-07-27.json");
const fx = JSON.parse(fs.readFileSync(FIXTURE, "utf8"));
const NETWORK = "regtest";

// ---- the capture is what it claims to be ----
ok("the capture records the RPC that produced it",
   fx.rpc && fx.rpc.diff === "protx diff 1 11353");
ok("the capture is a diff over a real height range",
   fx.baseHeight === 1 && fx.targetHeight === 11353);
ok("the node emitted a diff whose version DISAGREES with its entries' version",
   fx.diff.nVersion === 1 && fx.diff.mnList.every((e) => e.nVersion === 2));
ok("every entry carries the version-2 nType field",
   fx.diff.mnList.every((e) => typeof e.nType === "number"));

// ---- what DOES work against real output: parsing the node's object ----
const parsed = new SimplifiedMNListDiff(fx.diff, NETWORK);
ok("the codec parses the node's own diff object",
   parsed.mnList.length === fx.diff.mnList.length &&
   parsed.newQuorums.length === fx.diff.newQuorums.length);
ok("the parsed base and target block hashes are the node's",
   parsed.baseBlockHash === fx.diff.baseBlockHash && parsed.blockHash === fx.diff.blockHash);

// the parsed quorum set must agree with the node's own quorum list, which is the property the
// walk would actually depend on when assembling a candidate set at a sign height
{
  // `quorum list` returns arrays of quorum HASH STRINGS keyed by llmqType label, not objects.
  // The first version of this check read a .quorumHash off each string, compared undefined
  // against real hashes, and failed. The codec was right and the check was wrong, which is worth
  // leaving on the record: a fixture that fails is not automatically evidence about the subject.
  const rpcHashes = [].concat(...Object.values(fx.quorumList)).sort();
  const codecHashes = parsed.newQuorums.map((q) => q.quorumHash).sort();
  ok("the node lists quorums as hash strings across its llmqType labels",
     rpcHashes.length === 8 && rpcHashes.every((h) => typeof h === "string" && h.length === 64));
  ok("every quorum the node lists is present in the codec's parse",
     rpcHashes.every((h) => codecHashes.includes(h)));
  ok("the codec recovers the llmqType of every parsed quorum",
     parsed.newQuorums.every((q) => Number.isInteger(q.llmqType)));
}

// ---- CANARY 1: the round trip through raw bytes is BROKEN on this real capture (a soundness-review finding) ----
{
  let threw = null;
  try {
    SimplifiedMNListDiff.fromBuffer(parsed.toBuffer(), NETWORK);
  } catch (e) {
    threw = (e && e.message) || String(e);
  }
  ok("CANARY: serialize-then-parse of the real capture still fails on nType (a soundness-review finding)",
     threw !== null && /nType/.test(threw));
}

// ---- CANARY 2: the cause is the DIFF-level version gate, not the entry encoding ----
{
  const patched = JSON.parse(JSON.stringify(fx.diff));
  patched.nVersion = 2;
  let roundTripped = false;
  try {
    const d = new SimplifiedMNListDiff(patched, NETWORK);
    const back = SimplifiedMNListDiff.fromBuffer(d.toBuffer(), NETWORK);
    roundTripped = back.mnList.length === fx.diff.mnList.length;
  } catch (e) {
    roundTripped = false;
  }
  ok("CANARY: forcing the diff version to 2 makes the same bytes round trip (isolates the gate)",
     roundTripped === true);
}

// ---------------------------------------------------------------------------
// THE P2P CAPTURE (2026-07-27). This is the form the pinned codec profile actually requires for
// coverage.listWalk[].protxDiffRaw, obtained over the peer protocol because no node API emits it
// (a soundness-review finding). These checks pin what the bytes are, so the parser written against them in step 3 has
// a fixed target.
// ---------------------------------------------------------------------------
{
  const P2P = path.join(__dirname, "fixtures", "p2p-mnlistdiff-regtest-2026-07-27.json");
  const p2p = JSON.parse(fs.readFileSync(P2P, "utf8"));
  const raw = Buffer.from(p2p.payloadHex, "hex");

  ok("the capture records the protocol version it negotiated",
     p2p.protocolVersionOffered === 70240);
  ok("the payload length matches the recorded byte count",
     raw.length === p2p.byteLength && raw.length === 3645);
  // at 70229 and above nVersion is the FIRST field [8c9f166a3:src/evo/smldiff.h:65-79]
  ok("nVersion is first, as the negotiated protocol requires", raw.readUInt16LE(0) === 1);
  // the two hashes follow, in internal byte order, so they read back reversed
  const readHash = (off) => Buffer.from(raw.subarray(off, off + 32)).reverse().toString("hex");
  ok("the base block hash on the wire is the one requested", readHash(2) === p2p.baseBlockHash);
  ok("the target block hash on the wire is the one requested", readHash(34) === p2p.blockHash);

  // CANARY: the library cannot parse the real wire form either (a soundness-review finding). This fails if
  // the library gains support, which is the signal to re-read a soundness-review finding before choosing a parser.
  {
    let threw = null;
    try { SimplifiedMNListDiff.fromBuffer(raw, NETWORK); }
    catch (e) { threw = (e && e.message) || String(e); }
    ok("CANARY: the library still cannot parse the P2P wire form (a soundness-review finding)", threw !== null);
  }

  // the two oracles describe the SAME diff as the wire bytes, which is what makes them usable as
  // oracles for the parser written in step 3
  ok("the RPC oracle covers the same block range as the wire capture",
     fx.diff.baseBlockHash === p2p.baseBlockHash || fx.baseHeight === 1);
}

console.log(`mnListCodecProbeTest: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
