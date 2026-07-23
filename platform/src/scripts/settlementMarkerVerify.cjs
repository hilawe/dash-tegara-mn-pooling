/**
 * Design A reader-verification: given a DECODED L1 transfer transaction and the expected terms,
 * confirm it is a valid atomic membership transfer. This is the property that makes design A
 * reader-safe where the L2 supersede design was not (a soundness review): the payment is on L1 and a reader
 * can cold-verify it. Pure, no network, so it is unit-testable over sample decoded transactions
 * (the live two-party transaction CONSTRUCTION is the separate fresh-session custody build).
 *
 * Decoded tx shape (normalized from dash-cli decoderawtransaction, value in DUFFS):
 *   { vin: [{ txid, vout }], vout: [{ valueDuffs, scriptHex }] }
 *
 * A valid transfer must, all four:
 *   1. spend the expected PRIOR marker outpoint (txid, vout),
 *   2. pay the LEAVER at least the price (an output to the leaver's script >= priceDuffs),
 *   3. create the SUCCESSOR marker (an output to the joiner's declared marker script),
 *   4. COMMIT to the joiner's L2 candidate share (an OP_RETURN carrying its 32-byte content hash).
 */

// OP_RETURN with a single 32-byte push: 6a (OP_RETURN) 20 (push 32) <32 bytes>
function opReturn32(scriptHex) {
  const s = (scriptHex || "").toLowerCase();
  if (!s.startsWith("6a20")) return null;
  const data = s.slice(4, 4 + 64);
  return data.length === 64 ? data : null;
}

function verifyTransfer(tx, expected) {
  const reasons = [];
  const vin = tx.vin || [];
  const vout = tx.vout || [];

  const spentPrior = vin.some((i) =>
    i.txid === expected.priorMarker.txid && Number(i.vout) === Number(expected.priorMarker.vout));
  if (!spentPrior) reasons.push("prior marker outpoint not spent");

  const paidLeaver = vout.some((o) =>
    o.scriptHex === expected.leaverScriptHex && Number(o.valueDuffs) >= Number(expected.priceDuffs));
  if (!paidLeaver) reasons.push("leaver not paid at least the price");

  const madeMarker = vout.some((o) =>
    o.scriptHex === expected.successorMarkerScriptHex && Number(o.valueDuffs) >= 1);
  if (!madeMarker) reasons.push("successor marker output not created");

  const committed = vout.some((o) => opReturn32(o.scriptHex) === expected.candidateHashHex.toLowerCase());
  if (!committed) reasons.push("L2 candidate not committed in an OP_RETURN");

  return { ok: reasons.length === 0, reasons };
}

module.exports = { verifyTransfer, opReturn32 };
