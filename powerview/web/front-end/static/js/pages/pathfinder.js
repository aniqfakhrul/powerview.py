import { createGridPage } from '../components/grid/grid-page.js';
import { attachObjectSearch } from '../components/object-search.js';
import { renderSummary } from '../components/object-panel/summary.js';
import { createAPI } from '../core/api.js';
import { values } from '../core/directory.js';
import { button, element, setBusy } from '../core/dom.js';
import { aceTypeTone, aclColumns } from './pathfinder/columns.js';
import { aclEntries } from './pathfinder/records.js';

const DETAIL_FIELDS = [
  ['ObjectDN', 'Target'], ['ObjectSID', 'Target SID'], ['SecurityIdentifier', 'Trustee'], ['GrantedVia', 'Granted via'],
  ['ACEType', 'ACE type'], ['Rights', 'Rights'], ['ObjectAceType', 'Object-specific right'],
  ['AccessMask', 'Access mask'], ['Scope', 'Scope'], ['InheritanceType', 'Inherited object type'], ['ACEFlags', 'ACE flags'],
  ['ObjectAceFlags', 'Object ACE flags'], ['DEBUG', 'Parser note'],
];
const TONES = { ACEType: aceTypeTone };

const root = document.querySelector('#pathfinder');
const request = createAPI(new URL(root.dataset.apiRoot, location.origin));
const find = (name) => document.getElementById(`pathfinder-${name}`);
const form = find('form');
let query = null;
let completed = null;

const formValues = () => ({ identity: find('target').value.trim(), principal: find('principal').value.trim() });

function syncControls() {
  const { identity, principal } = formValues();
  find('depth').disabled = !principal;
  find('find').disabled = !identity && !principal;
}

function describeScope({ identity, security_identifier: principal, depth }) {
  if (!principal) return `ACEs on ${identity} for any principal`;
  const expansion = depth ? ` (+${depth} group level${depth === 1 ? '' : 's'})` : '';
  return `ACEs granted to ${principal}${expansion} ${identity ? `on ${identity}` : 'across the domain'}`;
}

function remember({ identity, security_identifier: principal, depth }) {
  const url = new URL(location.href);
  url.search = '';
  if (identity) url.searchParams.set('target', identity);
  if (principal) url.searchParams.set('principal', principal);
  if (principal) url.searchParams.set('depth', String(depth));
  history.replaceState(null, '', url);
}

function restore() {
  const params = new URL(location.href).searchParams;
  find('target').value = params.get('target') ?? '';
  find('principal').value = params.get('principal') ?? '';
  const depth = find('depth').querySelector(`option[value="${CSS.escape(params.get('depth') ?? '')}"]`);
  if (depth) find('depth').value = depth.value;
}

function detailRows(attributes) {
  return DETAIL_FIELDS
    .map(([key, label]) => ({ key, label, values: values(attributes[key]).filter((value) => value !== '').map(String) }))
    .filter((row) => row.values.length)
    .map(({ key, label, values: items }) => ({ label, values: items, tone: TONES[key]?.(items[0]) }));
}

function searchTarget(dn) {
  find('target').value = dn;
  find('principal').value = '';
  syncControls();
  form.requestSubmit();
  find('cancel').focus();
}

function exportRows() {
  if (!completed) return;
  const data = {
    query: completed,
    export_scope: 'Filtered rows',
    interpretation: 'Observed ACEs, not effective access. Group expansion follows memberOf. Unreadable descriptors and unsupported ACEs may be omitted.',
    aces: page.visibleEntries().map((entry) => entry.record.attributes),
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = `powerview-pathfinder-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

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
    actions(entry) {
      if (!entry.dn) return [];
      const label = 'Find all ACEs on this target';
      const control = button('', { iconName: 'search', className: 'icon-button', ariaLabel: label });
      control.title = label;
      control.addEventListener('click', () => searchTarget(entry.dn));
      return [control];
    },
    render(container, entry) {
      renderSummary(container, detailRows(entry.record.attributes));
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
    const refocus = loading ? form.contains(document.activeElement) : document.activeElement === find('cancel');
    setBusy(form, loading);
    find('cancel').hidden = !loading;
    find('cancel').disabled = false;
    find('export').disabled = loading || !completed;
    if (!loading) syncControls();
    if (refocus) find(loading ? 'cancel' : 'find').focus();
  },
});

const suggestions = [['principal', 'principal'], ['target', 'any']]
  .map(([name, kind]) => attachObjectSearch({ input: find(name), directory: page.directory, kind, onChoose: syncControls }));

form.addEventListener('submit', (event) => {
  event.preventDefault();
  for (const suggestion of suggestions) suggestion.close();
  const { identity, principal } = formValues();
  if (!identity && !principal) return;
  query = { depth: principal ? Number(find('depth').value) : 0, ...(identity ? { identity } : {}), ...(principal ? { security_identifier: principal } : {}) };
  find('hint').textContent = describeScope(query);
  remember(query);
  page.reload();
});
form.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !find('cancel').hidden) { event.preventDefault(); find('cancel').click(); }
});
for (const name of ['target', 'principal']) find(name).addEventListener('input', syncControls);
find('cancel').addEventListener('click', () => { completed = null; page.cancel(); });
find('export').addEventListener('click', exportRows);
restore();
syncControls();
page.status.idle('Pathfinder · Ready · Read-only');
