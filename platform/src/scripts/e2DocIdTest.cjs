/**
 * e2DocIdTest: the planned write identifier's pure module, driven against the driver's
 * previous inline formula (reproduced here verbatim) and the INSTALLED Platform generator.
 * The generator is REQUIRED for this test: byte-identity with the old derivation is the
 * claim step 3c makes, and an unperformed check never passes.
 */
"use strict";
const crypto = require("crypto");
const path = require("path");
const { pathToFileURL } = require("url");
const D = require("./e2DocId.cjs");
const formationCore = require("./formationCore.cjs");

let passed = 0, failed = 0;
const ok = (name, cond) => { if (cond) { passed++; console.log(`  PASS: ${name}`); } else { failed++; console.error(`  FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  let t = null;
  try { fn(); } catch (e) { t = e.message; }
  ok(`${name} (${t ? t.slice(0, 70) : "no throw"})`, t !== null && /e2DocId/.test(t) && re.test(t));
};

// THE OLD FORMULA, verbatim from e2DistributeRun.mjs at d0ca3e4 (and the transport runner's
// copy), reproduced here as the oracle; the module must be byte-identical to it
const oldEntropy = (poolId, epochIndex, type, subject) =>
  crypto.createHash("sha256").update(`tegara.e2.entropy.v1|${type}|${poolId}|${epochIndex}|${subject}`).digest();

const POOL = "5779c8c9".padEnd(64, "0");
const FUNDER = "7dad14b6".padEnd(64, "a");
const ACC = "c1".repeat(32);
// any two 32-byte identifiers in base58, as the runners pass the writer identity and the
// contract identifier (primitive strings)
const OWNER = "5jLZJF4RurvAkahXhLLHHgBisEDgs58v8AmP8w7cMqe";
const CONTRACT = "8sVj3E2yqQtV3f5mHdq2vG6x7PhZyM2QPZbYjVSNv9L";

const main = async () => {
  console.log("e2DocIdTest");
  const root = process.env.TEGARA_PLATFORM_ROOT || path.resolve(__dirname, "../..");
  const dppPath = require.resolve("pshenmic-dpp", { paths: [root] });
  const dpp = await import(pathToFileURL(dppPath).href);
  const generateId = dpp.DocumentWASM.generateId;
  ok("the installed generator is a function (the byte-identity check below needs it, and an unperformed check never passes)", typeof generateId === "function");
  // THE INSTALLED GENERATOR IS NOT A CONSTANT STUB: two entropies give two identifiers, and
  // the identifier changes with the owner too. This rejects a stub; it does not
  // authenticate the implementation, which is the acceptance stage's business.
  {
    const a = generateId("platformAccrual", OWNER, CONTRACT, new Uint8Array(Buffer.alloc(32, 1)));
    const b = generateId("platformAccrual", OWNER, CONTRACT, new Uint8Array(Buffer.alloc(32, 2)));
    // the owner varies with the CONTRACT FIXED, so this is owner-only dependence (the
    // confirmation's clarity note: the first fixture changed both at once)
    const c = generateId("platformAccrual", CONTRACT, CONTRACT, new Uint8Array(Buffer.alloc(32, 1)));
    const d2 = generateId("platformAccrual", OWNER, OWNER, new Uint8Array(Buffer.alloc(32, 1)));
    const s = (x) => (typeof x.base58 === "function" ? x.base58() : String(x));
    ok("the installed generator's identifiers VARY with the entropy alone, with the owner alone and with the contract alone (a constant stub would not pass)",
      s(a) !== s(b) && s(a) !== s(c) && s(a) !== s(d2) && formationCore.toId32(s(a)) !== null && formationCore.toId32(s(b)) !== null);
  }

  // ---- byte-identity with the old formula, over every type's subject grammar and TWO
  // pools (a derivation that hardcoded one pool would pass a single-pool matrix) ----
  const POOL2 = "9dc7527d".padEnd(64, "b");
  const cases = [
    ["platformAccrual", FUNDER, 0], ["platformAccrual", FUNDER, 7],
    ["transferReservation", ACC, 0], ["transferReceipt", ACC, 3],
    ["receiptProofPart", `${ACC}#1`, 0], ["receiptProofPart", `${ACC}#7`, 12],
    ["epochHeader", "header#0", 0], ["epochHeader", "header#41", 41],
  ];
  const ids = new Set();
  for (const poolId of [POOL, POOL2]) {
    for (const [type, subject, epochIndex] of cases) {
      const e = D.entropyForIn({ poolId, epochIndex, type, subject });
      const old = oldEntropy(poolId, epochIndex, type, subject);
      const mine = D.docIdForIn({ generateId, ownerId: OWNER, contractId: CONTRACT, poolId, epochIndex, type, subject });
      const oldId = generateId(type, OWNER, CONTRACT, new Uint8Array(old));
      const oldB58 = typeof oldId.base58 === "function" ? oldId.base58() : String(oldId);
      ids.add(mine.b58);
      ok(`${type} at epoch ${epochIndex} in pool ${poolId.slice(0, 4)}: the entropy is byte-identical to the old formula and the identifier equals the old derivation's (${mine.b58.slice(0, 8)}...)`,
        Buffer.compare(e, old) === 0 && Buffer.compare(mine.entropy, old) === 0 && mine.b58 === oldB58
        && mine.hex === formationCore.toId32(oldB58).toString("hex") && /^[0-9a-f]{64}$/.test(mine.hex));
    }
  }
  ok("the sixteen derivations are sixteen distinct identifiers (the pool and every other input reach the identifier)", ids.size === 16);
  ok("the maximum safe integer is an accepted epoch and the next integer is refused",
    Buffer.compare(D.entropyForIn({ poolId: POOL, epochIndex: Number.MAX_SAFE_INTEGER, type: "platformAccrual", subject: FUNDER }),
      oldEntropy(POOL, Number.MAX_SAFE_INTEGER, "platformAccrual", FUNDER)) === 0
    && (() => { try { D.entropyForIn({ poolId: POOL, epochIndex: Number.MAX_SAFE_INTEGER + 1, type: "platformAccrual", subject: FUNDER }); return false; } catch (e) { return /non-negative safe integer/.test(e.message); } })());
  // each field varied ALONE against the same base (the confirmation's clarity note: the
  // first fixture had no subject-only pair): the epoch alone, the pool alone, the subject
  // alone, and the type alone with the same subject
  {
    const base = { poolId: POOL, epochIndex: 1, type: "platformAccrual", subject: FUNDER };
    const e = (over) => D.entropyForIn({ ...base, ...over }).toString("hex");
    ok("the derivation is deterministic and distinct entropy follows from each field varied alone (epoch, pool, subject, and type with the same subject)",
      e({}) === e({})
      && new Set([e({}), e({ epochIndex: 2 }), e({ poolId: "1".repeat(64) }), e({ subject: "2".repeat(64) }),
        e({ type: "transferReceipt", subject: ACC }), e({ type: "transferReservation", subject: ACC })]).size === 6);
  }

  // ---- canonical-only inputs (the design's section 8): each refused by name ----
  const good = { poolId: POOL, epochIndex: 3, type: "platformAccrual", subject: FUNDER };
  throws("an uppercase pool identifier is refused", () => D.entropyForIn({ ...good, poolId: POOL.toUpperCase() }), /64-hex lowercase primitive string/);
  throws("a base58 pool identifier is refused", () => D.entropyForIn({ ...good, poolId: CONTRACT }), /64-hex lowercase primitive string/);
  throws("a byte-object pool identifier is refused", () => D.entropyForIn({ ...good, poolId: Buffer.from(POOL, "hex") }), /primitive string/);
  throws("a boxed-string pool identifier is refused", () => D.entropyForIn({ ...good, poolId: new String(POOL) }), /primitive string/);
  throws("a negative epoch is refused", () => D.entropyForIn({ ...good, epochIndex: -1 }), /non-negative safe integer/);
  throws("a fractional epoch is refused", () => D.entropyForIn({ ...good, epochIndex: 1.5 }), /non-negative safe integer/);
  throws("an unknown document type is refused", () => D.entropyForIn({ ...good, type: "platformAccruals" }), /type must be one of/);
  throws("a base58 funder subject is refused", () => D.entropyForIn({ ...good, subject: CONTRACT }), /64-hex lowercase identity/);
  throws("an uppercase accrual subject on a receipt is refused", () => D.entropyForIn({ ...good, type: "transferReceipt", subject: ACC.toUpperCase() }), /64-hex lowercase document identifier/);
  throws("a part subject with index 0 is refused", () => D.entropyForIn({ ...good, type: "receiptProofPart", subject: `${ACC}#0` }), /partIndex 1\.\.7/);
  throws("a part subject with index 8 is refused", () => D.entropyForIn({ ...good, type: "receiptProofPart", subject: `${ACC}#8` }), /partIndex 1\.\.7/);
  throws("a header subject naming another epoch is refused", () => D.entropyForIn({ ...good, type: "epochHeader", subject: "header#4" }), /names epoch 4 while the derivation is for epoch 3/);
  throws("a header subject with padded digits is refused even when it names the right epoch", () => D.entropyForIn({ ...good, type: "epochHeader", subject: "header#03" }), /canonical digits/);
  throws("a boxed-string subject is refused", () => D.entropyForIn({ ...good, subject: new String(FUNDER) }), /subject must be a primitive string/);
  throws("an epoch one above the safe-integer limit is refused", () => D.entropyForIn({ ...good, epochIndex: 9007199254740992 }), /non-negative safe integer/);
  throws("an empty owner identity is refused", () => D.docIdForIn({ ...good, generateId, ownerId: "", contractId: CONTRACT }), /ownerId must be a non-empty primitive string/);
  throws("an empty contract identifier is refused", () => D.docIdForIn({ ...good, generateId, ownerId: OWNER, contractId: "" }), /contractId must be a non-empty primitive string/);
  throws("a generator result carrying a string-valued base58 PROPERTY (not a method) is refused (the conversion is narrower than the old String(id) fallback)",
    () => D.docIdForIn({ ...good, generateId: () => ({ base58: OWNER }), ownerId: OWNER, contractId: CONTRACT }), /no base58 identifier/);
  // ---- EVERY INPUT IS READ ONCE, THROUGH ITS OWN DATA DESCRIPTOR (the preliminary review's
  // F1): an accessor is refused without being invoked, an inherited member is refused, and a
  // changing pool or type therefore cannot reach the hash or the generator ----
  {
    let poolReads = 0, typeReads = 0;
    const changingPool = Object.defineProperty({ ...good }, "poolId", { get: () => { poolReads += 1; return poolReads === 1 ? POOL : POOL.toUpperCase(); }, enumerable: true });
    let t1 = null; try { D.entropyForIn(changingPool); } catch (e) { t1 = e.message; }
    const changingType = Object.defineProperty({ ...good, generateId, ownerId: OWNER, contractId: CONTRACT }, "type",
      { get: () => { typeReads += 1; return typeReads <= 2 ? "platformAccrual" : "transferReceipt"; }, enumerable: true });
    let t2 = null; try { D.docIdForIn(changingType); } catch (e) { t2 = e.message; }
    ok(`F1: a pool supplied by a changing getter is refused by name with the getter NEVER invoked (reads ${poolReads})`,
      t1 !== null && /own DATA member/.test(t1) && poolReads === 0);
    ok(`F1: a type supplied by a changing getter is refused by name with the getter NEVER invoked (reads ${typeReads})`,
      t2 !== null && /own DATA member/.test(t2) && typeReads === 0);
    let t3 = null; try { D.entropyForIn(Object.create({ ...good })); } catch (e) { t3 = e.message; }
    ok("F1: inherited members are refused (the options must carry each input as its own data member)", t3 !== null && /required as an own data member/.test(t3));
  }
  throws("a subject carrying the entropy delimiter is refused", () => D.entropyForIn({ ...good, subject: `${FUNDER.slice(0, 63)}|` }), /entropy delimiter/);
  throws("a non-function generator is refused", () => D.docIdForIn({ ...good, generateId: "generateId", ownerId: OWNER, contractId: CONTRACT }), /generator function/);
  throws("a non-string owner identity is refused", () => D.docIdForIn({ ...good, generateId, ownerId: Buffer.from(POOL, "hex"), contractId: CONTRACT }), /ownerId must be a non-empty primitive string/);
  throws("a non-string contract identifier is refused", () => D.docIdForIn({ ...good, generateId, ownerId: OWNER, contractId: { toString: () => CONTRACT } }), /contractId must be a non-empty primitive string/);
  throws("a generator whose result does not decode to 32 bytes is refused", () => D.docIdForIn({ ...good, generateId: () => "not-an-identifier", ownerId: OWNER, contractId: CONTRACT }), /does not decode to 32 bytes/);
  throws("a generator returning nothing is refused", () => D.docIdForIn({ ...good, generateId: () => undefined, ownerId: OWNER, contractId: CONTRACT }), /no base58 identifier/);
  {
    // the generator receives exactly the validated inputs and the entropy bytes, in the
    // driver's argument order, and its base58 is what the module reports
    // a RECEIPT type here, so a derivation that always handed the generator one type is
    // caught, and the entropy argument must be a Uint8Array INSTANCE (the runner's previous
    // representation), not merely something Buffer.from would accept
    const seen = [];
    const fake = (type, owner, contract, entropy) => { seen.push([type, owner, contract, entropy instanceof Uint8Array && !Buffer.isBuffer(entropy), Buffer.from(entropy).toString("hex")]); return { base58: () => OWNER }; };
    const rc = { ...good, type: "transferReceipt", subject: ACC };
    const r = D.docIdForIn({ ...rc, generateId: fake, ownerId: OWNER, contractId: CONTRACT });
    ok("the generator is called once with (type, ownerId, contractId, entropy as a Uint8Array) in the driver's order, the type the caller's, and its base58 is reported with its hex",
      seen.length === 1 && seen[0][0] === "transferReceipt" && seen[0][1] === OWNER && seen[0][2] === CONTRACT && seen[0][3] === true
      && seen[0][4] === D.entropyForIn(rc).toString("hex") && r.b58 === OWNER && r.hex === formationCore.toId32(OWNER).toString("hex"));
  }

  console.log(`\ne2DocIdTest: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
};

main().catch((e) => { console.error(`e2DocIdTest: unexpected throw: ${e.message}`); process.exitCode = 1; });
