/**
 * Paginated document fetch (review finding F11, 2026-07-11). Platform caps a single
 * documents.get at 100 results, so every "whole ledger" query pages with a startAfter
 * cursor until a short page arrives. Callers that previously capped at 100 silently
 * under-reported on a larger ledger.
 */
const PAGE = 100;
// An absolute ceiling on pages in one fetchAll (a soundness-review finding). The loop's cursor is
// taken from the RETURNED page, so its progress depends entirely on what the
// node sends back: a node that answers every request with the same full page
// produces the same cursor every time and the walk never ends. Unlike the
// proved-query enumeration, nothing here checks that identifiers ascend, so
// there was no second rule making it terminate either. The sibling below,
// fetchUpTo, was already given a bound for the related concern of an unbounded
// collection; this is the same shape in the function beside it.
//
// Exceeding it THROWS rather than returning what was collected, because this
// function's whole purpose is that callers stop under-reporting on a large
// ledger: silently returning a prefix would reintroduce the defect it was
// written to fix. At 100 documents a page this admits a million documents.
const MAX_PAGES = 10000;

const fetchAll = async (client, type, query = {}) => {
  const out = [];
  let startAfter;
  let pages = 0;
  for (;;) {
    const page = await client.platform.documents.get(type, {
      ...query,
      limit: PAGE,
      ...(startAfter ? { startAfter } : {}),
    });
    out.push(...page);
    if (page.length < PAGE) return out;
    pages += 1;
    if (pages >= MAX_PAGES) {
      throw new Error(`fetchAll(${type}) exceeded ${MAX_PAGES} pages; refusing rather than returning a partial ledger`);
    }
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
