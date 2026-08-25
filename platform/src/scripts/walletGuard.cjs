/**
 * Hide consumed-outside-the-wallet's-sight outpoints from the wallet's UTXO view.
 *
 * A designated UTXO whose spend pays no wallet output is never marked spent by the
 * wallet library (the phantom-UTXO problem, observed live 2026-07-10). The rail's own
 * asset-lock builder filters these explicitly, but the SDK's INTERNAL asset-lock paths
 * (identities.register, identities.topUp) coin-select over account.getUTXOS() directly
 * and picked the phantom too (bad-txns-inputs-missingorspent at funder3 registration,
 * 2026-07-10 night). Wrapping getUTXOS once at the account level covers every consumer.
 *
 * The consumed list lives in the RAIL_STATE journal (railState.cjs) and is re-read from
 * .env.local on every call, so outpoints recorded mid-run are filtered too (review
 * finding F12, 2026-07-11). Call right after client.getWalletAccount() in any script
 * that can build an L1 transaction.
 */
const rail = require("./railState.cjs");
const { loadEnv } = require("./envStore.cjs");

const consumedNow = () => {
  // a soundness-review finding: a state error must SURFACE, never read as "nothing consumed". The old catch
  // here returned [] on any failure, which defeated railState's deliberate corruption
  // refusals: a malformed or unreadable state made every consumed outpoint reappear in
  // the wallet view, exactly the unchecked-never-means-passed shape the global rule
  // names. A legitimately EMPTY environment does not throw (rail.load returns the
  // fresh idle state with consumed []), so refusing on throw refuses only real errors.
  try {
    return rail.load(loadEnv()).consumed;
  } catch (e) {
    // reading e.message can itself throw (a broken or misbehaving getter); the refusal must
    // survive that too, wrapped rather than escaping unwrapped (external artifact check)
    let underlying;
    try { underlying = (e && e.message) || String(e); } catch { underlying = "(unprintable error)"; }
    const err = new Error("the consumed-output state cannot be read, so the wallet's " +
      "UTXO view cannot be trusted and no transaction should be built over it " +
      `(a soundness-review finding). Underlying: ${underlying}`);
    err.cause = e;
    throw err;
  }
};

const installConsumedFilter = (account) => {
  if (account.__consumedFilterInstalled) return account;
  const original = account.getUTXOS.bind(account);
  account.getUTXOS = (...args) => {
    const consumed = consumedNow();
    const utxos = original(...args);
    return consumed.length
      ? utxos.filter((u) => !consumed.includes(`${u.txId}:${u.outputIndex}`))
      : utxos;
  };
  account.__consumedFilterInstalled = true;
  return account;
};

module.exports = { installConsumedFilter };
