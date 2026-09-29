import { createGridPage } from '../components/grid/grid-page.js';
import { renderSummary } from '../components/object-panel/summary.js';
import { createAPI } from '../core/api.js';
import { element, setBusy } from '../core/dom.js';
import { aclColumns } from './pathfinder/columns.js';
import { aclEntries } from './pathfinder/records.js';

const root = document.querySelector('#pathfinder');
const request = createAPI(new URL(root.dataset.apiRoot, location.origin));
const find = (name) => document.getElementById(`pathfinder-${name}`);
const form = find('form');
let query = null;
let completed = null;

const page = createGridPage({
  root,
  endpoint: 'get/domainobjectacl',
  noun: { singular: 'ACE', plural: 'ACEs' },
  columnSet: aclColumns,
  search: false,
  autoLoad: false,
  deletable: false,
  initialMessage: { title: 'Find ACL relations', description: 'Enter a target or principal to find ACL relations.' },
  emptyMessage: { title: 'No matching ACEs returned', description: 'No ACEs were returned within this scope. Unreadable descriptors and unsupported entries may be omitted; this is not an effective-access verdict.' },
  details: {
    title: (entry) => `${entry.name} · ACE ${entry.record.attributes.ACEIndex}`,
    render(container, entry) {
      renderSummary(container, Object.entries(entry.record.attributes).map(([label, value]) => ({ label, values: value == null ? [] : [String(value)] })));
    },
  },
  async fetch({ signal, fresh }) {
    if (!query) return [];
    completed = null;
    find('export').disabled = true;
    const result = await request('get/domainobjectacl', { signal, body: { ...query, no_cache: fresh, resolveguids: true, no_vuln_check: true } });
    if (signal.aborted) return [];
    const entries = aclEntries(result);
    completed = { ...query, fresh, generated_at: new Date().toISOString() };
    return entries;
  },
  onLoadState(loading) {
    setBusy(form, loading);
    find('cancel').hidden = !loading;
    find('cancel').disabled = false;
    find('export').disabled = loading || !completed;
  },
});

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const identity = find('target').value.trim();
  const principal = find('principal').value.trim();
  if (!identity && !principal) {
    find('target').setCustomValidity('Enter a target or principal.');
    find('target').reportValidity();
    return;
  }
  query = { depth: Number(find('depth').value), ...(identity ? { identity } : {}), ...(principal ? { security_identifier: principal } : {}) };
  page.reload();
});
for (const name of ['target', 'principal']) find(name).addEventListener('input', () => find('target').setCustomValidity(''));
find('cancel').addEventListener('click', () => { completed = null; page.cancel(); });
find('export').addEventListener('click', () => {
  if (!completed) return;
  const data = { query: completed, export_scope: 'Filtered rows', interpretation: 'Observed ACEs, not effective access. Group expansion follows memberOf. Unreadable descriptors and unsupported ACEs may be omitted.', aces: page.visibleEntries().map((entry) => entry.record.attributes) };
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = `powerview-pathfinder-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
const params = new URL(location.href).searchParams;
find('target').value = params.get('target') ?? params.get('dn') ?? '';
find('principal').value = params.get('source') ?? '';
page.status.idle('Pathfinder · Ready · Read-only');
