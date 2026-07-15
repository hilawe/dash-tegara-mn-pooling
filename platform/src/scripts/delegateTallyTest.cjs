/**
 * Offline tests for the v5 targeted-delegation semantics and the format-2 canonical
 * rows (plain `node`, no devnet). The pre-v5 behavior is pinned first: with no
 * delegation map, computeTally must produce byte-identical hashes and outcomes.
 */
const { computeTally, tallyHash, canonicalMembers, tallyFromRows, validateCanonicalRows }
  = require("./tally.cjs");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.error(`FAIL: ${name}`); } };
const throws = (name, fn, re) => {
  try { fn(); fail++; console.error(`FAIL: ${name} (no error)`); }
  catch (e) { ok(name, re.test((e && e.message) || "")); }
};

const A = "3ytivjwDVivtumhsY8DG6boo6PEztScu6mr3v3QFFHHg";
const B = "4J21aMCugjeBaPfFBHqPWRneyLmMz2frS6cZK8YcuPxm";
const C = "BA13qbRCcjFwbZ4p9KoURBH8Zhh8EjAB8muDjYkkjvsf";
const MEMBERS = [{ owner: A, bps: 5000 }, { owner: B, bps: 3000 }, { owner: C, bps: 2000 }];
const CONTRACT = "Contract111111111111111111111111111111111111";
const POOL = "PoolId1111111111111111111111111111111111111";
const PROP = "12".repeat(32);
const hashOf = (t) => tallyHash(CONTRACT, POOL, PROP, t).toString("hex");

// 1. back-compat: the default argument and an explicit empty map are identical, and
// untargeted delegate still follows the net active vote
{
  const prefs = new Map([[A, "yes"], [B, "delegate"], [C, "no"]]);
  const t1 = computeTally(MEMBERS, prefs);
  const t2 = computeTally(MEMBERS, prefs, new Map());
  ok("back-compat identical hash", hashOf(t1) === hashOf(t2));
  ok("untargeted follows net (yes leads)", t1.final.yes === 8000 && t1.outcome === "yes");
}

// 2. targeted delegation follows the target's DIRECT choice
{
  const t = computeTally(MEMBERS, new Map([[A, "no"], [B, "delegate"], [C, "yes"]]),
    new Map([[B, C]]));
  ok("targeted follows target", t.final.yes === 5000 && t.final.no === 5000);
  ok("targeted rows carry delegateTo", t.rows.find((r) => r.owner === B).delegateTo === C);
}

// 3-5. unresolvable targets withhold: a chain, a self-target, a target with no preference
{
  const chain = computeTally(MEMBERS, new Map([[A, "yes"], [B, "delegate"], [C, "delegate"]]),
    new Map([[B, C], [C, A]]));
  ok("chain withholds the middle hop", chain.final.yes === 5000 + 2000 // C targets A directly
    && chain.weights.withheld === 3000); // B targeted C, whose choice is not direct
  const self = computeTally(MEMBERS, new Map([[A, "yes"], [B, "delegate"]]), new Map([[B, B]]));
  ok("self-target withholds", self.weights.withheld === 3000 + 2000); // B self, C no pref
  const missing = computeTally(MEMBERS, new Map([[A, "yes"], [B, "delegate"]]), new Map([[B, C]]));
  ok("target without preference withholds", missing.weights.withheld === 3000 + 2000);
}

// 6. round-trip: canonical rows (format 2) rebuild the identical tally and hash
{
  const t = computeTally(MEMBERS, new Map([[A, "no"], [B, "delegate"], [C, "yes"]]),
    new Map([[B, C]]));
  const rows = canonicalMembers(t);
  const rebuilt = tallyFromRows(rows, 2);
  ok("fv2 round-trip hash", hashOf(rebuilt) === hashOf(t));
  ok("fv2 round-trip outcome", rebuilt.outcome === t.outcome);
  // the same rows must FAIL format-1 validation (delegateTo is not a format-1 key)
  throws("fv1 rejects delegateTo rows", () => validateCanonicalRows(rows, 1), /not a format-1 row/);
}

// 7. format-2 validation specifics
{
  const base = [{ owner: A, bps: 5000, choice: "yes" },
    { owner: B, bps: 5000, choice: "delegate", delegateTo: C }].sort((a, b) => (a.owner < b.owner ? -1 : 1));
  ok("fv2 valid rows pass", validateCanonicalRows(base, 2) === base);
  const onDirect = base.map((r) => r.owner === A ? { ...r, delegateTo: C } : r);
  throws("delegateTo on a direct choice fails", () => validateCanonicalRows(onDirect, 2),
    /carries delegateTo with choice/);
  const selfD = base.map((r) => r.owner === B ? { ...r, delegateTo: B } : r);
  throws("self-delegation fails", () => validateCanonicalRows(selfD, 2), /delegates to itself/);
  throws("unknown format version fails", () => validateCanonicalRows(base, 3), /unknown format version/);
  // a base58-alphabet string that does not DECODE to 32 bytes is not an identity
  // (re-check finding: the alphabet regex alone let "1".repeat(43) pass)
  const fakeId = base.map((r) => r.owner === B ? { ...r, delegateTo: "1".repeat(43) } : r);
  throws("non-32-byte delegateTo fails", () => validateCanonicalRows(fakeId, 2), /not a base58 identity id/);
  const fakeOwner = [{ owner: "1".repeat(43), bps: 10000, choice: "yes" }];
  throws("non-32-byte owner fails", () => validateCanonicalRows(fakeOwner, 2), /not a base58 identity id/);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
