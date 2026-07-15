/**
 * The ONE place votePreference documents become tally inputs (holistic-round F6: the
 * governor and the cast-receipt publisher each built these maps themselves, and only
 * one of them read delegateTo, so the two operator tools could compute DIFFERENT
 * tallies, hashes, and L1 instructions from the same v5 ledger). Presence-based on
 * purpose: a pre-v5 document simply has no delegateTo, so no version gate is needed on
 * the READ side, and any tool using this helper resolves targeted delegation
 * identically.
 */
const { Identifier } = require("@dashevo/wasm-dpp");

const prefsToMaps = (prefs) => ({
  choiceByOwner: new Map(prefs.map((d) => [d.getOwnerId().toString(), d.toObject().choice])),
  delegateToByOwner: new Map(prefs
    .filter((d) => d.toObject().delegateTo)
    .map((d) => [d.getOwnerId().toString(),
      Identifier.from(Buffer.from(d.toObject().delegateTo)).toString()])),
});

module.exports = { prefsToMaps };
