/**
 * The funder-facing client: a usable front over the self-sovereign Track A actions, the
 * view and driver a pool member actually needs. Every write is created and signed by the
 * funder's OWN identity; there is no operator login and nothing custodial in the flow.
 *
 * This file is now a thin ROUTER (holistic-round restructuring): it builds the shared
 * context (clientContext.cjs) and dispatches to one command module per subcommand under
 * commands/. The per-command behavior and its honest-readback discipline live in those
 * modules; nothing here does domain work.
 *
 * Subcommands (node src/scripts/funderClient.cjs <cmd> [...]):
 *   portfolio            my identity, credit balance, shares, requests, and earnings (default)
 *   pools                every pool on the ledger with its recorded share total
 *   earnings             my reward accruals, per pool per epoch, with the sum
 *   deposit <duffs>      convert my own L1 DASH into credits at MY identity
 *   compound <poolId> <duffs|all> | status | release <id> --verified-never-landed
 *                        turn earned rewards into contribution (crash-recoverable journal)
 *   autopay on|off|status|run   the standing payout preference and its sweep
 *   limits               my balance and the honest withdrawal expectations
 *   addkey               add the recovery key pair (auth + transfer), generated off-seed
 *   onboard <depositDuffs> [<poolId> <joinDuffs>]   the one-flow entry for a fresh member
 *   watch [loop <sec>]   diff my ledger view against a local watermark and report changes
 *   pledge <poolId> <duffs> [rewardAddress] | pledges <poolId>   FORMING-pool participation
 *   reserve <poolId> <slotNo> [rewardAddress] | slots <poolId>   the on-ledger slot book
 *                        (LEDGER=v6/v7; under v7 the pool document carries the slot
 *                        economics and claims are sizeless and cancellable)
 *   join <poolId> <duffs> | exit <poolId> <duffs>   membership requests
 *   requests | cancel <requestId | slotClaimId>      my requests and the self-sovereign undo
 *                        (under LEDGER=v6 cancel also deletes a pledgeSlot claim while forming)
 *   withdraw <duffs> [address]   credits back to L1 at my own address
 *   vote <poolId> <proposalHash> <choice> [delegateTo] | votes | myrow   governance
 *
 * WHO=funderN selects among the registered funder identities (default funder1). Run like
 * the other scripts (container, --network host, CA mounted, .env.local + state dir + src
 * mounted).
 */
const { buildContext } = require("./clientContext.cjs");

// the router: subcommand -> module. Aliases share one module that branches on ctx.cmd
// (join/exit) or ctx.args (pledge/pledges, compound sub-verbs), exactly as before.
const ROUTES = {
  portfolio: "portfolio", pools: "pools", earnings: "earnings", deposit: "deposit",
  onboard: "onboard", compound: "compound", autopay: "autopay", watch: "watch",
  addkey: "addkey", limits: "limits", pledge: "pledge", pledges: "pledge",
  join: "join", exit: "join", requests: "requests", vote: "vote", myrow: "myrow",
  votes: "votes", withdraw: "withdraw", cancel: "cancel", reserve: "reserve", slots: "reserve",
};

(async () => {
  const ctx = await buildContext();
  try {
    await ctx.installFilter();
    const route = ROUTES[ctx.cmd];
    if (!route) {
      throw new Error(`unknown command "${ctx.cmd}" (${Object.keys(ROUTES).join(" | ")})`);
    }
    const run = require(`./commands/${route}.cjs`);
    await run(ctx);
  } catch (e) {
    console.error("ERROR:", (e && e.message) || e);
    process.exitCode = 1;
  } finally {
    await ctx.disconnect();
  }
})();
