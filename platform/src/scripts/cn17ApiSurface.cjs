/**
 * a soundness-review finding probe, phase A (OFFLINE): inspect the installed dash SDK / wasm-dpp API surface
 * to determine which document transitions the client can ORIGINATE. The a soundness-review finding finding
 * says the consensus core has native document transferable/transfer/purchase/set-price;
 * this phase asks the separate, load-bearing question of whether the SHIPPED SDK exposes
 * a builder for them, or only create/replace/delete. No network, no writes.
 *
 * Run in the tegara-sdk container (it needs the wasm to initialize):
 *   docker run --rm --network host -e NETWORK=regtest \
 *     -v "$PWD/src:/app/src" tegara-sdk node src/scripts/cn17ApiSurface.cjs
 */
const Dash = require("dash");

const proto = (o) => {
  const names = new Set();
  let cur = o;
  while (cur && cur !== Object.prototype) {
    for (const n of Object.getOwnPropertyNames(cur)) names.add(n);
    cur = Object.getPrototypeOf(cur);
  }
  return [...names].filter((n) => n !== "constructor").sort();
};

(async () => {
  const clientOpts = { network: process.env.NETWORK || "regtest" };
  if (process.env.DAPI_HOST) clientOpts.dapiAddresses = [{
    host: process.env.DAPI_HOST, port: parseInt(process.env.DAPI_PORT || "2443", 10), protocol: "https",
  }];
  const client = new Dash.Client(clientOpts);
  try {
    // force dpp/wasm init the way the platform facade does
    await client.platform.initialize();
    const platform = client.platform;
    const dpp = platform.dpp;

    console.log("=== client.platform.documents methods ===");
    console.log(proto(platform.documents).join(", "));

    console.log("\n=== dpp.document (DocumentFacade) methods ===");
    console.log(dpp && dpp.document ? proto(dpp.document).join(", ") : "(no dpp.document)");

    console.log("\n=== wasm-dpp named exports (transition/price/transfer-relevant) ===");
    const wasm = require("@dashevo/wasm-dpp");
    const keys = Object.keys(wasm).sort();
    const relevant = keys.filter((k) => /Transition|Transfer|Purchase|Price|Transferable|Trade|Batch|DocumentTransitions/i.test(k));
    console.log(relevant.join("\n"));

    console.log("\n=== DocumentTransitions builder methods ===");
    if (wasm.DocumentTransitions) {
      try {
        const dt = new wasm.DocumentTransitions();
        console.log(proto(dt).join(", "));
      } catch (e) { console.log("could not construct:", e && e.message); }
    } else {
      console.log("(no DocumentTransitions export)");
    }

    console.log("\n=== StateTransitionTypes enum ===");
    console.log(wasm.StateTransitionTypes ? JSON.stringify(wasm.StateTransitionTypes) : "(none)");

    // Does the document type meta-schema recognize transferable/tradeMode? Build a tiny
    // contract with a transferable, direct-purchase document type and try to validate it
    // OFFLINE via wasm-dpp. This tells us whether the CONTRACT-AUTHORING path is reachable
    // even if the transition-origination path is not.
    console.log("\n=== offline contract validation with transferable + tradeMode doc type ===");
    const docSchema = {
      listing: {
        type: "object",
        transferable: 1,   // 0 = never, 1 = always (document-type-level keyword)
        tradeMode: 1,      // 0 = none, 1 = direct purchase
        properties: {
          label: { type: "string", maxLength: 63, position: 0 },
        },
        required: ["label"],
        additionalProperties: false,
      },
    };
    try {
      const id = require("@dashevo/wasm-dpp").Identifier;
      // use a throwaway 32-byte owner id
      const ownerId = id.from(Buffer.alloc(32, 7));
      const created = await platform.contracts.create(docSchema, { getId: () => ownerId, getBalance: () => 1e12 });
      console.log("contracts.create ACCEPTED transferable+tradeMode doc type (offline build ok)");
      const obj = created.toObject ? created.toObject() : null;
      if (obj) console.log("  serialized doc type keys:", Object.keys(obj.documentSchemas ? obj.documentSchemas.listing : (obj.documents ? obj.documents.listing : {})).join(", "));
    } catch (e) {
      console.log("contracts.create REJECTED:", (e && e.message) || String(e));
      console.log("  ctor:", e && e.constructor && e.constructor.name);
    }
  } catch (e) {
    console.error("SURFACE PROBE ERROR:", (e && e.message) || e);
    if (e && e.stack) console.error(e.stack.split("\n").slice(0, 8).join("\n"));
    process.exitCode = 1;
  } finally {
    if (client.disconnect) await client.disconnect();
  }
})();
