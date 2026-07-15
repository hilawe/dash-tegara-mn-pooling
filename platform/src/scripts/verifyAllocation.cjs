/**
 * Offline verifier for an on-ledger completion receipt's embedded allocation (v8).
 * No devnet, no SDK: given a receipt's own bytes, it recomputes the allocationHash from the
 * embedded allocationRows, checks the bytes are canonical, and confirms the allocation binds to
 * the expected contract. This is the self-contained third-party property, an auditor checks a
 * receipt without the operator's local files and without a Platform query.
 *
 * It does NOT prove the pool's shares still exist or match (they are mutable and drift after
 * completion); it proves the receipt's own allocation is well-formed, canonical, and unaltered.
 * See docs/COMPLETION_RECEIPT_SPEC.md, the honesty ceiling.
 *
 *   node verifyAllocation.cjs <receipt.json>
 *
 * The input JSON carries the receipt fields, with byteArrays as hex:
 *   {
 *     "contractId":        "<base58 pool-ledger contract id>",   // the contract you expect
 *     "allocationRowsHex": "<hex of the embedded UTF-8 preimage bytes>",
 *     "allocationHashHex": "<hex of the 32-byte allocationHash>",
 *     "poolId":            "<base58, optional top-level correspondence check>",
 *     "targetDuffs":       "<base-10 string, optional>",
 *     "participantCount":  <integer, optional>
 *   }
 * As a convenience, "allocationRowsUtf8" may be given instead of "allocationRowsHex".
 */
const fs = require("fs");
const core = require("./formationCore.cjs");

const die = (msg) => { console.error(msg); process.exit(2); };

const path = process.argv[2];
if (!path) die("usage: node verifyAllocation.cjs <receipt.json>");

let doc;
try { doc = JSON.parse(fs.readFileSync(path, "utf8")); }
catch (e) { die(`cannot read/parse ${path}: ${(e && e.message) || e}`); }

if (!doc || typeof doc !== "object" || Array.isArray(doc)) die("receipt JSON must be an object");
if (typeof doc.contractId !== "string") die("receipt JSON needs a base58 \"contractId\" (the contract you expect)");
// validate the hex before decoding: Buffer.from(hex) silently drops a trailing half-byte and stops
// at the first non-hex char, so unvalidated input could be truncated junk that still "verifies"
let rowsBuf = null;
if (doc.allocationRowsHex != null && doc.allocationRowsUtf8 != null) {
  die("give allocationRowsHex OR allocationRowsUtf8, not both (ambiguous which payload is verified)");
}
if (doc.allocationRowsHex != null) {
  if (typeof doc.allocationRowsHex !== "string" || !/^([0-9a-f]{2})+$/i.test(doc.allocationRowsHex)) {
    die("allocationRowsHex must be a non-empty even-length hex string");
  }
  rowsBuf = Buffer.from(doc.allocationRowsHex, "hex");
} else if (typeof doc.allocationRowsUtf8 === "string") {
  rowsBuf = Buffer.from(doc.allocationRowsUtf8, "utf8");
}
if (rowsBuf === null) die("receipt JSON needs \"allocationRowsHex\" (or \"allocationRowsUtf8\")");
if (typeof doc.allocationHashHex !== "string" || !/^[0-9a-f]{64}$/i.test(doc.allocationHashHex)) {
  die("receipt JSON needs a 64-hex \"allocationHashHex\"");
}

const receipt = {
  allocationRows: rowsBuf,
  allocationHash: Buffer.from(doc.allocationHashHex, "hex"),
  poolId: doc.poolId,
  targetDuffs: doc.targetDuffs,
  participantCount: doc.participantCount,
};

const r = core.verifyReceiptAllocation(doc.contractId, receipt);
if (!r.ok) {
  console.log(`FAIL: ${r.reason}`);
  process.exit(1);
}
// decode the embedded allocation for a human-readable echo
const arr = JSON.parse(rowsBuf.toString("utf8"));
const rows = arr[5];
console.log("OK: the receipt's embedded allocation is well-formed, canonical, and unaltered.");
console.log(`  contract:      ${doc.contractId}`);
console.log(`  pool:          ${r.poolId}`);
console.log(`  target:        ${r.targetDuffs} duffs`);
console.log(`  participants:  ${r.participantCount}`);
console.log(`  allocationHash ${doc.allocationHashHex.toLowerCase()} (recomputed, matches)`);
for (const [owner, amountDuffs, bps, scriptHex] of rows) {
  console.log(`    - ${owner}  ${amountDuffs} duffs  ${bps} bps  reward ${scriptHex}`);
}
console.log("\nNote: this checks the receipt alone. It does not prove the pool's shares still match " +
  "(shares are mutable); for that, query the pool's live share documents.");
process.exit(0);
