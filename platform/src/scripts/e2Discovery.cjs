/**
 * The SHARED finalized-epoch discovery primitive (E2 build spec, the frozen audit
 * section's literal discovery contract; named as this module by the fold-confirmation
 * pass, finding 3). Its ONLY intended consumers are e2Distribute.cjs (the run-start
 * lag measurement) and e2Audit.cjs (interval resolution); both inject their own
 * fetch, so writer and audit cannot measure different universes from one ledger
 * state. e2DiscoveryTest.cjs carries a SOURCE-LEVEL net (an import check that
 * activates when the consumer files exist, plus a no-reimplementation sweep);
 * that net does not EXECUTE the consumers, so proof of use arrives with the
 * consumers' own injected-fetch execution tests when they land (the batched
 * checker's finding 9 narrowed this claim).
 *
 * The contract, implemented exactly and only:
 *   - consecutive INCLUSIVE ranges of fixed width W (a positive integer 1..1024,
 *     default 64) starting at the resolved startEpoch: [s, s+W-1], [s+W, s+2W-1], ...
 *   - EVERY nonempty response must equal the EXACT gapless ascending sequence from
 *     its requested start through its highest epoch h; anything else REFUSES
 *     (the gapless-ascending property of finalized epochs is a C1 PINNING
 *     REQUIREMENT, cited at protocol source when C1 closes, never asserted here);
 *   - a response with h below its range's top establishes h as the newest
 *     finalized and ENDS discovery;
 *   - a full response continues at the next range; a LATER EMPTY response
 *     terminates at the preceding range's top;
 *   - a full response clipped at the u32 ceiling terminates AT the ceiling;
 *   - an EMPTY FIRST response is the DISTINCT EMPTY RESULT;
 *   - discovery is UNPROVED until construction C1 closes, like every universe
 *     read, and the result SAYS SO: `proved` is copied from the injected fetch's
 *     own declaration and this module never upgrades it.
 *
 * The fetch is injected as `fetchRange(start, end)` and resolves to
 * `{ epochs, proved }`, where `epochs` is the array of epoch objects the route
 * returned for the inclusive range (each carrying an integer `number`) and
 * `proved` is that route's honest strength. This module validates SHAPE and
 * drives the range machine; it performs no transport and no proof verification
 * (those are the injecting caller's pins).
 */

const U32_MAX = 4294967295;

const discoverFinalizedEpochs = async (startEpoch, fetchRange, opts = {}) => {
  if (!Number.isSafeInteger(startEpoch) || startEpoch < 0 || startEpoch > U32_MAX) {
    throw new Error(`discovery startEpoch ${startEpoch} is not a u32 epoch index; refusing`);
  }
  const W = opts.width === undefined ? 64 : opts.width;
  if (!Number.isSafeInteger(W) || W < 1 || W > 1024) {
    throw new Error(`discovery width ${W} is outside 1..1024; refusing`);
  }
  if (typeof fetchRange !== "function") {
    throw new Error("discovery needs an injected fetchRange(start, end); refusing");
  }

  let proved = true; // downgraded by the FIRST response; empty-first keeps the first response's word
  let rangeStart = startEpoch;
  let first = true;
  const epochs = [];

  for (;;) {
    const rangeEnd = Math.min(rangeStart + W - 1, U32_MAX);
    const resp = await fetchRange(rangeStart, rangeEnd);
    if (!resp || !Array.isArray(resp.epochs) || typeof resp.proved !== "boolean") {
      throw new Error("discovery fetch returned a malformed result (need { epochs, proved }); refusing");
    }
    proved = proved && resp.proved;

    if (resp.epochs.length === 0) {
      if (first) {
        // the DISTINCT EMPTY RESULT: nothing finalized at or after the start
        return { empty: true, newestFinalized: null, epochs: [], proved: resp.proved };
      }
      // a LATER empty response terminates at the preceding range's top
      return { empty: false, newestFinalized: rangeStart - 1, epochs, proved };
    }

    // the response-shape refusal: the EXACT gapless ascending sequence from the
    // requested start through its highest epoch, nothing else
    for (let i = 0; i < resp.epochs.length; i++) {
      const e = resp.epochs[i];
      if (!e || !Number.isSafeInteger(e.number)) {
        throw new Error(`discovery response entry ${i} has no integer epoch number; refusing`);
      }
      if (e.number !== rangeStart + i) {
        throw new Error(`discovery response is not the exact gapless ascending sequence from ${rangeStart} ` +
          `(entry ${i} is epoch ${e.number}, expected ${rangeStart + i}); refusing`);
      }
    }
    const h = rangeStart + resp.epochs.length - 1;
    if (h > rangeEnd) {
      throw new Error(`discovery response overruns its requested range (${h} > ${rangeEnd}); refusing`);
    }
    epochs.push(...resp.epochs);

    if (h < rangeEnd) {
      // partial tail: h is the newest finalized, discovery ends
      return { empty: false, newestFinalized: h, epochs, proved };
    }
    if (rangeEnd === U32_MAX) {
      // a full response clipped at the u32 ceiling terminates AT the ceiling
      return { empty: false, newestFinalized: U32_MAX, epochs, proved };
    }
    first = false;
    rangeStart = rangeEnd + 1;
  }
};

module.exports = { discoverFinalizedEpochs, U32_MAX };
