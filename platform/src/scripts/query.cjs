/**
 * Paginated document fetch (review finding F11, 2026-07-11). Platform caps a single
 * documents.get at 100 results, so every "whole ledger" query pages with a startAfter
 * cursor until a short page arrives. Callers that previously capped at 100 silently
 * under-reported on a larger ledger.
 */
const PAGE = 100;

const fetchAll = async (client, type, query = {}) => {
  const out = [];
  let startAfter;
  for (;;) {
    const page = await client.platform.documents.get(type, {
      ...query,
      limit: PAGE,
      ...(startAfter ? { startAfter } : {}),
    });
    out.push(...page);
    if (page.length < PAGE) return out;
    startAfter = page[page.length - 1].getId();
  }
};

/**
 * Bounded fetch (batch-6 re-check): stop after `max` documents so an unbounded,
 * spammable collection (e.g. open-creation vote observations) cannot force verify to
 * pull and materialize the whole set. Returns { docs, truncated } where truncated is
 * true when at least one more document existed (a real MAX+1 was seen), so callers
 * can report the cap loudly instead of silently. The query's own orderBy decides
 * which `max` are kept; document that choice at the call site.
 */
const fetchUpTo = async (client, type, max, query = {}) => {
  const docs = [];
  let startAfter;
  while (docs.length <= max) {
    const want = Math.min(PAGE, max + 1 - docs.length);
    const page = await client.platform.documents.get(type, {
      ...query,
      limit: want,
      ...(startAfter ? { startAfter } : {}),
    });
    docs.push(...page);
    if (page.length < want) break; // exhausted
    startAfter = page[page.length - 1].getId();
  }
  const truncated = docs.length > max;
  return { docs: truncated ? docs.slice(0, max) : docs, truncated };
};

module.exports = { fetchAll, fetchUpTo };
