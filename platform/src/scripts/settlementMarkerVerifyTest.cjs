/**
 * Offline test of the design-A reader verification (plain `node`). Proves a reader accepts a
 * well-formed atomic transfer and rejects each way it can be malformed, over sample DECODED
 * transactions. No network, no funds, no live construction.
 */
const { verifyTransfer, opReturn32 } = require("./settlementMarkerVerify.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.error("FAIL:", name); } };

const PRIOR = { txid: "aa".repeat(32), vout: 1 };
const LEAVER_SPK = "76a914" + "11".repeat(20) + "88ac";       // leaver P2PKH
const JOINER_MARKER_SPK = "76a914" + "22".repeat(20) + "88ac"; // joiner's next marker P2PKH
const CANDIDATE = "cc".repeat(32);
const PRICE = 500_00000000;

const expected = { priorMarker: PRIOR, priceDuffs: PRICE, leaverScriptHex: LEAVER_SPK,
  successorMarkerScriptHex: JOINER_MARKER_SPK, candidateHashHex: CANDIDATE };

// a well-formed atomic transfer
const good = {
  vin: [{ txid: PRIOR.txid, vout: 1 }, { txid: "bb".repeat(32), vout: 0 }], // prior marker + joiner payment input
  vout: [
    { valueDuffs: PRICE, scriptHex: LEAVER_SPK },              // pay the leaver the price
    { valueDuffs: 100000, scriptHex: JOINER_MARKER_SPK },      // joiner's successor marker
    { valueDuffs: 0, scriptHex: "6a20" + CANDIDATE },          // OP_RETURN commit to the candidate
    { valueDuffs: 250000, scriptHex: "76a914" + "33".repeat(20) + "88ac" }, // joiner change
  ],
};

ok("valid transfer accepted", verifyTransfer(good, expected).ok === true);

// 1. prior marker NOT spent
{
  const t = { ...good, vin: [{ txid: "bb".repeat(32), vout: 0 }] };
  const r = verifyTransfer(t, expected);
  ok("prior marker not spent -> rejected", !r.ok && r.reasons.includes("prior marker outpoint not spent"));
}

// 2. leaver UNDERPAID
{
  const t = { ...good, vout: good.vout.map((o) => o.scriptHex === LEAVER_SPK ? { ...o, valueDuffs: PRICE - 1 } : o) };
  const r = verifyTransfer(t, expected);
  ok("leaver underpaid -> rejected", !r.ok && r.reasons.some((x) => x.includes("price")));
}

// 3. leaver PAID TO THE WRONG SCRIPT
{
  const t = { ...good, vout: good.vout.map((o) => o.scriptHex === LEAVER_SPK ? { ...o, scriptHex: "76a914" + "99".repeat(20) + "88ac" } : o) };
  ok("wrong payout script -> rejected", verifyTransfer(t, expected).ok === false);
}

// 4. NO successor marker
{
  const t = { ...good, vout: good.vout.filter((o) => o.scriptHex !== JOINER_MARKER_SPK) };
  const r = verifyTransfer(t, expected);
  ok("no successor marker -> rejected", !r.ok && r.reasons.some((x) => x.includes("successor marker")));
}

// 5. NO commitment
{
  const t = { ...good, vout: good.vout.filter((o) => !o.scriptHex.startsWith("6a")) };
  const r = verifyTransfer(t, expected);
  ok("no OP_RETURN commitment -> rejected", !r.ok && r.reasons.some((x) => x.includes("candidate")));
}

// 6. WRONG commitment (commits to a different candidate)
{
  const t = { ...good, vout: good.vout.map((o) => o.scriptHex.startsWith("6a") ? { valueDuffs: 0, scriptHex: "6a20" + "ee".repeat(32) } : o) };
  ok("wrong candidate hash -> rejected", verifyTransfer(t, expected).ok === false);
}

// 7. OP_RETURN parser: only a 32-byte push counts
ok("opReturn32 reads a 32-byte push", opReturn32("6a20" + CANDIDATE) === CANDIDATE);
ok("opReturn32 rejects a non-OP_RETURN", opReturn32(LEAVER_SPK) === null);
ok("opReturn32 rejects a wrong-length push", opReturn32("6a04deadbeef") === null);

console.log(`settlementMarkerVerifyTest: ${pass} passed, ${fail} failed`);
if (fail) process.exitCode = 1;
