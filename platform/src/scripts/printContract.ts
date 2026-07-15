import { poolLedgerContract } from "../contract/poolLedger.js";

// Quick sanity check: the contract is well-formed JSON and each document type has indices.
const docTypes = Object.keys(poolLedgerContract);
console.log(`pool-ledger contract: ${docTypes.length} document types`);
for (const [name, def] of Object.entries(poolLedgerContract)) {
  const props = Object.keys((def as any).properties).length;
  const idx = ((def as any).indices ?? []).length;
  console.log(`  ${name.padEnd(18)} ${props} properties, ${idx} indices`);
}
console.log(JSON.stringify(poolLedgerContract, null, 2));
