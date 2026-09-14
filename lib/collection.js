import { createHash } from 'node:crypto';
// Fetch every page, retaining usable evidence if a later request fails.
export async function collectPages(fetchPage, { key = 'objects', limit = 500 } = {}) {
  const items = [];
  const dictionary = new Map();
  let first = null;
  let offset = 0;
  let pages = 0;
  let total = null;
  const seenPages = new Set();
  const finish = (error = null) => ({
    ok: !error,
    data: { ...(first || {}), [key]: items, 'objects-dictionary': [...dictionary.values()], total: total ?? items.length },
    error,
    coverage: { status: error ? (pages ? 'partial' : 'failed') : 'complete', pages, returned: items.length, total, nextOffset: offset }
  });
  for (;;) {
    const result = await fetchPage({ limit, offset });
    if (!result.ok) return finish(result.error);
    const data = result.data || {};
    first ||= data;
    const batch = data[key] ?? (key === 'objects' ? data.packages : undefined);
    if (!Array.isArray(batch)) return finish({ error: `Response did not contain ${key}.`, phase: 'pagination' });
    if (batch.length) {
      const signature = createHash('sha256').update(JSON.stringify(batch)).digest('hex');
      if (seenPages.has(signature)) return finish({ error: 'Server repeated a page instead of advancing.', phase: 'pagination' });
      seenPages.add(signature);
    }
    const reportedTotal = Number(data.total);
    if (data.total !== undefined && Number.isFinite(reportedTotal)) total = reportedTotal;
    // "to" describes consumed positions, including section-wrapped rules.
    const reportedTo = Number(data.to);
    const next = Number.isFinite(reportedTo) && data.to !== undefined ? reportedTo : offset + batch.length;
    if (batch.length && next <= offset) return finish({ error: 'Pagination stopped advancing.', phase: 'pagination' });
    items.push(...batch);
    for (const object of data['objects-dictionary'] || data.objectsDictionary || []) {
      if (object.uid) dictionary.set(object.uid, object);
    }
    pages += 1;
    offset = next;
    if (total !== null && offset >= total) return finish();
    if (!batch.length) return total !== null && offset < total
      ? finish({ error: 'Empty page before reported total.', phase: 'pagination' }) : finish();
    if (total === null && batch.length < limit) return finish();
  }
}

export function scopedCommandKey(session, command, body, serialize) {
  return serialize([session.baseUrl || '', session.sid || '', session.domain || '', command, body]);
}

export function collectionOutcome(result) {
  if (!result) return { status: 'not-assessed', errors: [] };
  if (result.coverage) return { ...result.coverage, errors: result.error ? [result.error] : [] };
  const errors = [...(result.errors || []), ...(result.error ? [result.error] : [])];
  if (result.skipped) return { status: 'not-assessed', errors };
  if (result.ok && !errors.length) return { status: 'complete', errors: [] };
  const unsupported = errors.length && errors.every(error => /requested api command.*not found/i.test(JSON.stringify(error)));
  const evidence = (result.rows?.length || result.objects?.length || result.evidenceTables?.some(t => t.rows?.length)
    || result.rowsByPolicy?.size || result.data);
  return { status: unsupported ? 'unsupported' : evidence ? 'partial' : 'failed', errors };
}
