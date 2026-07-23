/**
 * a soundness-review finding LIVE PROBE (throwaway namespace). Verifies, end to end on the local devnet,
 * whether the installed dash SDK (7.0.0) + wasm-dpp (4.0.0) can deliver the native Dash
 * Platform document purchase/transfer path that a soundness-review finding identified in the consensus core.
 *
 * Two SEPARATE clients with UNRELATED mnemonics stand in for a seller (A) and a buyer (B):
 *   1. publish a throwaway contract whose `listing` document type is transferable + direct
 *      purchase (transferable:1, tradeMode:1);
 *   2. A creates a listing document;
 *   3. A lists it at a price (update-price / set-price);
 *   4. B (unrelated mnemonic) purchases it;
 *   5. confirm ownership moves to B and the price credits move B -> A in ONE transition;
 *   6. probe whether a purchase can be constrained to a NAMED buyer.
 *
 * The probe self-funds both wallets through the seed Core RPC (CORE_RPC_URL) so it runs in
 * one shot; state persists in a scratch JSON so a re-run resumes. It NEVER touches the
 * canonical .env.local. Every transition-origination attempt is isolated and its exact
 * failure is reported, because whether the SHIPPED SDK exposes a builder for these
 * transitions (as opposed to the consensus core merely understanding them) is the
 * load-bearing question a soundness-review finding left open.
 *
 * Run:
 *   docker run --rm --network host -e NETWORK=regtest -e DAPI_HOST=192.168.5.2 \
 *     -e GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/ca.crt \
 *     -e CORE_RPC_URL=http://dashmate:PASS@127.0.0.1:20302 \
 *     -v ~/.dashmate/local_1/platform/gateway/ssl/bundle.crt:/ca.crt:ro \
 *     -v "$PWD/src:/app/src" -v "$PWD/.env.cn17.json:/app/.env.cn17.json" \
 *     tegara-sdk node src/scripts/cn17LiveProbe.cjs
 */
const fs = require("fs");
const http = require("http");
const Dash = require("dash");
const { Identifier } = require("@dashevo/wasm-dpp");

const STATE_PATH = "/app/.env.cn17.json";
const MINER = process.env.MINER_ADDR || "yPm9eim1tSjhAbxNmjVYcKumbpfrkwGhVL";
const FUND_DASH = 30;                 // per wallet
const FUND_DUFFS = FUND_DASH * 1e8;

const loadState = () => { try { return JSON.parse(fs.readFileSync(STATE_PATH, "utf8") || "{}"); } catch { return {}; } };
const saveState = (s) => fs.writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const DASHfmt = (d) => (Number(d) / 1e8).toFixed(8);
const line = (s) => console.log(s);
const ctorOf = (e) => (e && e.constructor && e.constructor.name) || "";
const msgOf = (e) => (e && e.message) || (ctorOf(e) !== "Object" && ctorOf(e)) || String(e);

// --- minimal Core RPC (self-funding) ---
function coreRpc(method, params = []) {
  const url = new URL(process.env.CORE_RPC_URL);
  const body = JSON.stringify({ jsonrpc: "1.0", id: "cn17", method, params });
  const opts = {
    hostname: url.hostname, port: url.port, path: "/", method: "POST",
    auth: `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`,
    headers: { "content-type": "text/plain", "content-length": Buffer.byteLength(body) },
  };
  return new Promise((resolve, reject) => {
    const req = http.request(opts, (res) => {
      let d = ""; res.on("data", (c) => (d += c));
      res.on("end", () => {
        try { const j = JSON.parse(d); if (j.error) reject(new Error(JSON.stringify(j.error))); else resolve(j.result); }
        catch (e) { reject(new Error(`rpc parse: ${d.slice(0, 200)}`)); }
      });
    });
    req.on("error", reject); req.write(body); req.end();
  });
}
const mine = async (n = 1) => coreRpc("generatetoaddress", [n, MINER]);

function newClient(mnemonic) {
  const opts = { network: process.env.NETWORK || "regtest", wallet: { mnemonic: mnemonic || null } };
  if (process.env.DAPI_HOST) opts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  return new Dash.Client(opts);
}

// ensure a wallet has funds; returns the synced account
async function ensureFunded(client, label) {
  const account = await client.getWalletAccount();
  let bal = account.getTotalBalance();
  if (bal >= 10 * 1e8) { line(`  ${label} wallet already funded: ${DASHfmt(bal)} DASH`); return account; }
  const addr = account.getUnusedAddress().address;
  line(`  funding ${label} wallet at ${addr} with ${FUND_DASH} DASH ...`);
  await coreRpc("sendtoaddress", [addr, FUND_DASH]);
  await mine(2);
  // wait for the SDK wallet to observe the confirmed coins
  for (let i = 0; i < 40 && bal < 10 * 1e8; i++) {
    await sleep(3000);
    bal = account.getTotalBalance();
    if (i % 5 === 0) line(`    ${label} balance ${DASHfmt(bal)} DASH (waiting for sync) ...`);
    if (bal < 10 * 1e8 && i % 8 === 7) await mine(1);
  }
  if (bal < 10 * 1e8) throw new Error(`${label} wallet did not observe funds (balance ${DASHfmt(bal)})`);
  line(`  ${label} wallet funded: ${DASHfmt(bal)} DASH`);
  return account;
}

async function ensureIdentity(client, state, key, label, fundDuffs) {
  if (state[key]) { line(`  ${label} identity (existing): ${state[key]}`); return client.platform.identities.get(state[key]); }
  line(`  registering ${label} identity (fund ${DASHfmt(fundDuffs)} DASH of credits) ...`);
  const idn = await client.platform.identities.register(fundDuffs);
  state[key] = idn.getId().toString(); saveState(state);
  line(`  ${label} identity registered: ${state[key]}`);
  return idn;
}

// the transferable + direct-purchase contract
function listingContractDef() {
  return {
    listing: {
      type: "object",
      transferable: 1,   // 0 never, 1 always
      tradeMode: 1,      // 0 none, 1 direct purchase
      properties: {
        label: { type: "string", maxLength: 63, position: 0 },
        shareRef: { type: "string", maxLength: 63, position: 1 },
      },
      required: ["label", "$createdAt"],
      additionalProperties: false,
    },
  };
}

async function main() {
  if (!process.env.CORE_RPC_URL) { console.error("need CORE_RPC_URL for self-funding"); process.exit(2); }
  const state = loadState();

  const clientA = newClient(state.MNEMONIC_A);
  const clientB = newClient(state.MNEMONIC_B);
  try {
    line("=== a soundness-review finding LIVE PROBE ===");

    // --- wallets ---
    line("\n[1] wallets (two unrelated mnemonics)");
    await clientA.getWalletAccount();
    if (!state.MNEMONIC_A) { state.MNEMONIC_A = clientA.wallet.exportWallet(); saveState(state); line("  generated mnemonic A"); }
    await clientB.getWalletAccount();
    if (!state.MNEMONIC_B) { state.MNEMONIC_B = clientB.wallet.exportWallet(); saveState(state); line("  generated mnemonic B"); }
    line(`  A mnemonic head: ${state.MNEMONIC_A.split(" ").slice(0, 3).join(" ")} ...`);
    line(`  B mnemonic head: ${state.MNEMONIC_B.split(" ").slice(0, 3).join(" ")} ...`);
    line(`  unrelated: ${state.MNEMONIC_A !== state.MNEMONIC_B}`);

    await ensureFunded(clientA, "A");
    await ensureFunded(clientB, "B");

    // --- identities ---
    line("\n[2] identities");
    let idA = await ensureIdentity(clientA, state, "ID_A", "A (seller)", 500000000);  // 5 DASH: contract publish + listing
    let idB = await ensureIdentity(clientB, state, "ID_B", "B (buyer)", 800000000);   // 8 DASH: cover a 5-DASH purchase + fees
    line(`  A credits: ${idA.getBalance()}   B credits: ${idB.getBalance()}`);

    // --- publish the transferable + purchase contract (owned by A) ---
    line("\n[3] publish throwaway contract with transferable + tradeMode(direct purchase) listing type");
    if (!state.CONTRACT) {
      const contract = await clientA.platform.contracts.create(listingContractDef(), idA);
      await clientA.platform.contracts.publish(contract, idA);
      state.CONTRACT = contract.getId().toString(); saveState(state);
      line(`  PUBLISHED contract ${state.CONTRACT}`);
    } else line(`  contract (existing): ${state.CONTRACT}`);

    // re-open both clients with the app registered so documents.* resolves the type
    const withApp = (mnemonic) => {
      const opts = { network: process.env.NETWORK || "regtest", wallet: { mnemonic },
        apps: { probe: { contractId: state.CONTRACT } } };
      if (process.env.DAPI_HOST) opts.dapiAddresses = [{ host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https" }];
      return new Dash.Client(opts);
    };
    await clientA.disconnect(); await clientB.disconnect();
    const A = withApp(state.MNEMONIC_A), B = withApp(state.MNEMONIC_B);
    await A.getWalletAccount(); await B.getWalletAccount();
    idA = await A.platform.identities.get(state.ID_A);
    idB = await B.platform.identities.get(state.ID_B);

    // fetch the published contract object to inspect the recognized doc-type config live
    const liveContract = await A.platform.contracts.get(state.CONTRACT);
    let docTypeKeys = "(n/a)";
    try {
      const co = liveContract.toObject();
      const schemas = co.documentSchemas || co.documents || {};
      docTypeKeys = Object.keys(schemas.listing || {}).join(", ");
    } catch (e) { docTypeKeys = `inspect failed: ${msgOf(e)}`; }
    line(`  live contract listing doc-type keys: ${docTypeKeys}`);

    // --- A creates a listing document ---
    line("\n[4] A creates a listing document");
    let listing;
    {
      const doc = await A.platform.documents.create("probe.listing", idA, { label: "pool-share-42", shareRef: "poolX/slot3" });
      await A.platform.documents.broadcast({ create: [doc] }, idA);
      listing = doc;
      state.LISTING = doc.getId().toString(); saveState(state);
      line(`  created listing ${state.LISTING}, owner ${doc.getOwnerId().toString()}`);
    }
    const refetchListing = async (client) => (await client.platform.documents.get("probe.listing", { where: [["$id", "==", Identifier.from(state.LISTING)]] }))[0];

    const PRICE_DUFFS = 5 * 1e8; // 5 DASH list price
    const PRICE_CREDITS = BigInt(PRICE_DUFFS) * 1000n;

    // --- [5] LIST AT A PRICE: try every SDK path to originate a set-price/update-price transition ---
    line(`\n[5] list at a price (${DASHfmt(PRICE_DUFFS)} DASH => ${PRICE_CREDITS} credits): probe every SDK origination path`);
    const dppA = A.platform.dpp;
    const nonceObj = async (identity, key = "$id") => {
      const cid = Identifier.from(state.CONTRACT);
      const n = await A.platform.nonceManager.bumpIdentityContractNonce(identity.getId(), cid);
      return { [identity.getId().toString()]: { [cid.toString()]: n.toString() } };
    };

    const attempts = [];
    const tryOriginate = async (name, fn) => {
      try { const r = await fn(); attempts.push({ name, ok: true, detail: r || "built/accepted" }); line(`  [try] ${name}: SUCCEEDED (${r || "built"})`); }
      catch (e) { attempts.push({ name, ok: false, detail: `${ctorOf(e)}: ${msgOf(e).slice(0, 200)}` }); line(`  [try] ${name}: refused -> ${ctorOf(e)}: ${msgOf(e).slice(0, 200)}`); }
    };

    // 5a: high-level facade with an updatePrice/setPrice/transfer/purchase key
    for (const key of ["updatePrice", "setPrice", "price", "transfer", "purchase"]) {
      await tryOriginate(`documents.broadcast({${key}:[doc]})`, async () => {
        const fresh = await refetchListing(A);
        try { fresh.set("$price", PRICE_CREDITS); } catch {}
        await A.platform.documents.broadcast({ [key]: [fresh] }, idA);
        return "broadcast returned";
      });
    }

    // 5b: low-level dpp.document.createStateTransition with each key (authoritative Rust-converter test)
    for (const key of ["updatePrice", "setPrice", "transfer", "purchase", "create"]) {
      await tryOriginate(`dpp.document.createStateTransition({${key}:[doc]})`, async () => {
        const fresh = await refetchListing(A);
        try { fresh.set("$price", PRICE_CREDITS); } catch {}
        const st = dppA.document.createStateTransition({ [key]: [fresh] }, await nonceObj(idA));
        return `built ${st && st.constructor && st.constructor.name}`;
      });
    }

    // 5c: can ExtendedDocument even carry a $price system field?
    await tryOriginate("ExtendedDocument.set('$price')", async () => {
      const fresh = await refetchListing(A);
      fresh.set("$price", PRICE_CREDITS);
      const got = fresh.get("$price");
      return `set ok, read back = ${got}`;
    });

    // --- [6] PURCHASE by B: try every origination path ---
    line("\n[6] purchase by B (unrelated mnemonic): probe every SDK origination path");
    const dppB = B.platform.dpp;
    const nonceObjB = async () => {
      const cid = Identifier.from(state.CONTRACT);
      const n = await B.platform.nonceManager.bumpIdentityContractNonce(idB.getId(), cid);
      return { [idB.getId().toString()]: { [cid.toString()]: n.toString() } };
    };
    for (const key of ["purchase", "buy"]) {
      await tryOriginate(`B documents.broadcast({${key}:[doc]})`, async () => {
        const fresh = await refetchListing(B);
        try { fresh.set("$price", PRICE_CREDITS); } catch {}
        await B.platform.documents.broadcast({ [key]: [fresh] }, idB);
        return "broadcast returned";
      });
    }
    await tryOriginate("B dpp.document.createStateTransition({purchase:[doc]})", async () => {
      const fresh = await refetchListing(B);
      try { fresh.set("$price", PRICE_CREDITS); } catch {}
      const st = dppB.document.createStateTransition({ purchase: [fresh] }, await nonceObjB());
      return `built ${st && st.constructor && st.constructor.name}`;
    });

    // --- read-back and summary ---
    line("\n[7] read back listing ownership + balances");
    const finalListing = await refetchListing(A);
    line(`  listing owner now: ${finalListing ? finalListing.getOwnerId().toString() : "(gone)"}`);
    line(`  seller A (${state.ID_A}) credits: ${(await A.platform.identities.get(state.ID_A)).getBalance()}`);
    line(`  buyer  B (${state.ID_B}) credits: ${(await B.platform.identities.get(state.ID_B)).getBalance()}`);

    line("\n=== ORIGINATION ATTEMPT SUMMARY ===");
    for (const a of attempts) line(`  ${a.ok ? "OK  " : "FAIL"} ${a.name} :: ${a.detail}`);
    // count ONLY trade actions (a plain create succeeding is not a trade; exclude it and the
    // read-only $price setter probe so the verdict reflects the load-bearing question)
    const isTrade = (name) => /updatePrice|setPrice|\bprice\b|transfer|purchase|buy/i.test(name);
    const anyTradeOk = attempts.some((a) => a.ok && isTrade(a.name) && /createStateTransition|broadcast/.test(a.name));
    line(`\nRESULT: a document ${anyTradeOk ? "purchase/transfer/set-price transition WAS originable via the installed SDK" : "purchase/transfer/set-price transition could NOT be originated via the installed (official) SDK; only plain create/replace/delete build"}`);

    await A.disconnect(); await B.disconnect();
  } catch (e) {
    console.error("\nPROBE ERROR:", msgOf(e));
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 10).join("\n"));
    process.exitCode = 1;
    try { await clientA.disconnect(); } catch {}
    try { await clientB.disconnect(); } catch {}
  }
}
main();
