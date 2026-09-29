import { createDashboardInspector } from './dashboard/inspector.js';
import { beginLoading, skeletonRows } from '../components/loading.js';
import { createAPI } from '../core/api.js';
import { button, element, icon } from '../core/dom.js';
import { createStatus } from '../components/status.js';
import { sources, signals } from './dashboard/signals.js';

const root = document.querySelector('#dashboard');
const request = createAPI(new URL(root.dataset.apiRoot, location.origin));
const status = createStatus();
const find = (id) => document.getElementById(id);
const format = new Intl.NumberFormat();
const refresh = find('dashboard-refresh');
const exportButton = find('dashboard-export');
const filter = find('evidence-filter');
const signalButtons = new Map();
const daysSelect = find('dashboard-days');
const DAYS_KEY = 'powerview.dashboard.inactiveDays';
let days = 90;
try {
  const saved = localStorage.getItem(DAYS_KEY);
  if ([...daysSelect.options].some((option) => option.value === saved)) days = Number(saved);
} catch { /* per-viewer convenience only */ }
daysSelect.value = String(days);
const fill = (value) => value.replaceAll('{days}', String(days));
let data = {};
let failures = {};
let active = signals.find((signal) => signal.key === new URL(location.href).searchParams.get('signal')) ?? signals[0];
let selected = new URL(location.href).searchParams.has('signal');
let loading = false;
let loadingDelayed = false;
let domainDN = '';

createDashboardInspector({ root, status, getRootDN: () => Object.values(data)[0]?.root_dn, onSaved: () => load(true) });

const pending = (source) => loading && !data[source] && !failures[source];
const placeholder = (build) => (loadingDelayed ? build() : []);

function bar(width) {
  const node = element('span', 'loading-bar');
  node.style.width = width;
  return node;
}

function skeletonItem(className, ...children) {
  const item = element('div', `loading-row ${className}`.trim());
  item.setAttribute('aria-hidden', 'true');
  item.append(...children);
  return item;
}

function busy(host, sources) {
  const waiting = sources.some(pending);
  host.setAttribute('aria-busy', String(waiting));
  return waiting;
}

function objectLink(record, label = record.name, page = 'explorer') {
  if (!record.dn) return element('span', '', label);
  const link = element('a', 'dashboard__object', label);
  const url = new URL(root.dataset[page] ?? root.dataset.explorer, location.origin);
  url.searchParams.set('dn', record.dn);
  link.href = url;
  link.title = record.dn;
  link.dataset.inspectDn = record.dn;
  return link;
}

for (const [source, label] of [['users', 'Users'], ['computers', 'Computers']]) {
  find('dashboard-signals').append(element('h3', '', label));
  for (const signal of signals.filter((item) => item.source === source)) {
    const control = button('', { className: 'dashboard__signal' });
    const count = element('span', 'dashboard__signal-count', '—');
    const label = element('span', '', fill(signal.label));
    control.append(label, count);
    control.setAttribute('aria-controls', 'evidence-rows');
    control.addEventListener('click', () => {
      active = signal;
      selected = true;
      filter.value = '';
      const url = new URL(location.href);
      url.searchParams.set('signal', signal.key);
      history.replaceState(null, '', url);
      renderEvidence(true);
    });
    signalButtons.set(signal.key, { control, count, label });
    find('dashboard-signals').append(control);
  }
}

function renderEvidence(resetScroll = false) {
  for (const signal of signals) {
    const result = data[signal.source]?.findings[signal.key];
    const { control, count, label } = signalButtons.get(signal.key);
    label.textContent = fill(signal.label);
    control.setAttribute('aria-pressed', String(signal.key === active.key));
    control.dataset.matches = String(Boolean(result?.count));
    if (pending(signal.source)) count.replaceChildren(...placeholder(() => [bar('18px')]));
    else count.textContent = result ? format.format(result.count) : '—';
    control.title = result ? `${format.format(result.count)} matching accounts` : failures[signal.source] ? 'Source unavailable' : 'Waiting for source';
  }
  find('evidence-title').textContent = fill(active.label);
  find('evidence-description').textContent = fill(active.description);
  const result = data[active.source]?.findings[active.key];
  filter.disabled = !result;
  const query = filter.value.trim().toLowerCase();
  const objects = (result?.objects ?? []).filter((record) => `${record.name} ${record.dn} ${record.evidence}`.toLowerCase().includes(query));
  const waiting = pending(active.source);
  busy(find('dashboard-signals'), ['users', 'computers']);
  find('evidence-total').textContent = result ? `${format.format(result.count)} ${result.count === 1 ? 'match' : 'matches'}` : waiting ? '' : 'Not evaluated';
  find('evidence-count').textContent = result
    ? `${query ? `${format.format(objects.length)} of ` : ''}${format.format(result.objects.length)} sampled ${result.objects.length === 1 ? 'object' : 'objects'} · ${format.format(result.count)} total ${result.count === 1 ? 'match' : 'matches'}`
    : waiting ? '' : 'Source unavailable · Refresh to retry';
  const rows = objects.map((record) => {
    const row = element('tr');
    const name = element('td');
    name.append(objectLink(record, record.name, active.source));
    const inspect = element('td');
    if (record.dn) {
      const link = objectLink(record, '');
      link.className = 'icon-button';
      link.setAttribute('aria-label', `Inspect ${record.name}`);
      link.append(icon('open'));
      inspect.append(link);
    }
    row.append(name, element('td', '', record.evidence), inspect);
    return row;
  });
  find('evidence-rows').replaceChildren(...(waiting ? placeholder(() => skeletonRows(['', '', ''], 6)) : rows));
  if (resetScroll) root.querySelector('.dashboard__table-scroll').scrollTop = 0;
  const empty = find('evidence-empty');
  empty.hidden = rows.length > 0 || waiting;
  empty.textContent = waiting ? ''
    : !result ? `${sources[active.source]} could not be read. Refresh to retry; this signal has not been evaluated.`
      : result.count === 0 ? 'No matches in the returned directory data.' : 'No sampled objects match this filter.';
}

function renderInventory() {
  busy(find('dashboard-inventory'), ['users', 'computers', 'inventory']);
  for (const key of ['users', 'computers', 'groups', 'ous', 'gpos', 'trusts']) {
    const source = ['users', 'computers'].includes(key) ? key : 'inventory';
    const value = data[source]?.counts[source === 'inventory' ? key : 'total'];
    const count = root.querySelector(`[data-count="${key}"]`);
    const detail = root.querySelector(`[data-detail="${key}"]`);
    if (pending(source)) {
      count.replaceChildren(...placeholder(() => [bar('44px')]));
      detail.replaceChildren(...placeholder(() => [bar('96px')]));
      continue;
    }
    count.textContent = value == null ? '—' : format.format(value);
    detail.textContent = value == null
      ? 'Unavailable'
      : source === 'inventory' ? 'Visible in this domain' : `${format.format(data[source].counts.enabled)} enabled · ${format.format(data[source].counts.disabled)} disabled${data[source].counts.unknown ? ` · ${format.format(data[source].counts.unknown)} unknown` : ''}`;
  }
}

const known = (value, suffix = '') => value == null ? 'Not readable' : `${format.format(value)}${suffix}`;
const duration = (value, unit) => {
  if (value == null) return 'Not readable';
  if (value === 'never' || value === 0 || value >= 922337203685) return 'No expiry';
  const amount = value / unit;
  return `${format.format(amount)} ${unit === 86400 ? amount === 1 ? 'day' : 'days' : amount === 1 ? 'minute' : 'minutes'}`;
};

function renderPolicy() {
  const host = find('dashboard-policy');
  const result = data.domain;
  if (busy(host, ['domain'])) {
    host.replaceChildren(...placeholder(() => {
      const list = element('dl');
      list.append(...Array.from({ length: 9 }, (_, index) => skeletonItem('', bar(`${40 + (index * 13) % 30}%`), bar('48px'))));
      return [list];
    }));
    return;
  }
  if (!result) {
    host.replaceChildren(element('p', 'dashboard__empty', 'Domain policy unavailable. Refresh to retry.'));
    return;
  }
  const policy = result.policy;
  const flags = policy.pwdProperties;
  const fields = [
    ['Minimum password length', known(policy.minPwdLength, ' characters')],
    ['Password history', known(policy.pwdHistoryLength, ' passwords')],
    ['Maximum password age', duration(policy.maxPwdAge, 86400)],
    ['Minimum password age', policy.minPwdAge === 0 ? '0 days' : duration(policy.minPwdAge, 86400)],
    ['Lockout threshold', policy.lockoutThreshold === 0 ? 'No lockout' : known(policy.lockoutThreshold, ' attempts')],
    ['Lockout duration', policy.lockoutThreshold === 0 ? 'Not applicable' : policy.lockoutDuration === 0 || policy.lockoutDuration === 'never' ? 'Until an administrator unlocks' : duration(policy.lockoutDuration, 60)],
    ['Password complexity', flags == null ? 'Not readable' : flags & 1 ? 'Required' : 'Not required'],
    ['Reversible encryption', flags == null ? 'Not readable' : flags & 16 ? 'Enabled' : 'Disabled'],
    ['Machine-account quota', known(policy['ms-DS-MachineAccountQuota'])],
  ];
  const list = element('dl');
  for (const [label, value] of fields) {
    const row = element('div');
    row.append(element('dt', '', label), element('dd', '', value));
    list.append(row);
  }
  host.replaceChildren(list);
}

function renderSystems() {
  const result = data.computers;
  const systems = find('dashboard-systems');
  const controllers = find('dashboard-controllers');
  const waiting = busy(systems, ['computers']);
  busy(controllers, ['computers']);
  if (!result) find('systems-total').textContent = find('controllers-total').textContent = '';
  if (waiting) {
    systems.replaceChildren(...placeholder(() => {
      const distribution = element('div', 'dashboard__distribution');
      distribution.append(...[62, 48, 40, 34, 26].map((width) => {
        const label = element('div', 'dashboard__bar-label');
        label.append(bar(`${width}%`), bar('24px'));
        return skeletonItem('', label, element('div', 'dashboard__bar'));
      }));
      return [distribution];
    }));
    controllers.replaceChildren(...placeholder(() => [objectSkeleton(2)]));
    return;
  }
  if (!result) {
    const message = 'Computer inventory unavailable. Refresh to retry.';
    systems.replaceChildren(element('p', 'dashboard__empty', message));
    controllers.replaceChildren(element('p', 'dashboard__empty', message));
    return;
  }
  const { counts } = result;
  find('systems-total').textContent = `${format.format(counts.total)} computers`;
  find('controllers-total').textContent = format.format(counts.controllers);
  const distribution = element('div', 'dashboard__distribution');
  const items = result.systems.slice(0, 5);
  const other = result.systems.slice(5).reduce((sum, item) => sum + item.count, 0);
  if (other) items.push({ name: 'Other operating systems', count: other });
  for (const item of items) {
    const row = element('div');
    const label = element('div', 'dashboard__bar-label');
    label.append(element('span', '', item.name), element('strong', '', format.format(item.count)));
    const bar = element('div', 'dashboard__bar');
    bar.setAttribute('aria-hidden', 'true');
    const fill = element('span');
    fill.style.width = `${counts.total ? item.count / counts.total * 100 : 0}%`;
    bar.append(fill);
    row.append(label, bar);
    distribution.append(row);
  }
  systems.replaceChildren(items.length ? distribution : element('p', 'dashboard__empty', 'No computers returned.'));
  systems.append(element('p', 'dashboard__note', `${format.format(counts.missing_logon)} enabled computers have no readable replicated logon timestamp. OS names are directory values, not a patch assessment.`));
  const list = element('div', 'dashboard__object-list');
  for (const record of result.controllers) {
    const row = element('div');
    row.append(objectLink(record, record.host || record.name, 'computers'), element('p', '', `${record.os} · ${record.enabled ? 'Enabled' : 'Disabled'}`));
    list.append(row);
  }
  controllers.replaceChildren(result.controllers.length ? list : element('p', 'dashboard__empty', 'No domain controllers identified in returned account-control values.'));
  controllers.append(element('p', 'dashboard__note', counts.controllers > result.controllers.length ? `Showing the first ${result.controllers.length} of ${format.format(counts.controllers)} controllers.` : 'Identified from domain-controller account flags. Reachability and replication health are not tested.'));
}

function objectSkeleton(count) {
  const list = element('div', 'dashboard__object-list');
  list.append(...Array.from({ length: count }, () => {
    const detail = element('p');
    detail.append(bar('55%'));
    return skeletonItem('', bar('40%'), detail);
  }));
  return list;
}

function renderTrusts() {
  const result = data.inventory;
  const host = find('dashboard-trust-list');
  find('trusts-total').textContent = result ? format.format(result.counts.trusts) : '';
  if (busy(host, ['inventory'])) {
    host.replaceChildren(...placeholder(() => [objectSkeleton(2)]));
    return;
  }
  if (!result) {
    host.replaceChildren(element('p', 'dashboard__empty', 'Trust inventory unavailable. Refresh to retry.'));
    return;
  }
  const list = element('div', 'dashboard__object-list');
  for (const record of result.trusts) {
    const row = element('div');
    const direction = ['Disabled', 'Inbound · partner trusts this domain', 'Outbound · this domain trusts partner', 'Bidirectional'][record.direction] ?? 'Direction not readable';
    const flags = record.attributes;
    const scope = flags == null ? 'Attributes not readable' : flags & 32 ? 'Within forest' : flags & 8 ? 'Forest transitive' : 'Not marked forest transitive';
    row.append(objectLink(record, record.partner || record.name), element('p', '', direction), element('p', '', scope));
    list.append(row);
  }
  host.replaceChildren(result.trusts.length ? list : element('p', 'dashboard__empty', 'No trust objects returned in this domain.'));
  host.append(element('p', 'dashboard__note', result.counts.trusts > result.trusts.length ? `Showing the first ${result.trusts.length} of ${format.format(result.counts.trusts)} trusts.` : 'Direction is relative to this domain. Trust objects do not establish connectivity or effective access.'));
}

function renderCollection() {
  const errors = find('dashboard-errors');
  errors.replaceChildren(...Object.entries(failures).map(([source, message]) => element('p', '', `${sources[source]} unavailable: ${message}`)));
  errors.hidden = !Object.keys(failures).length;
  const loaded = Object.keys(data).length;
  const summary = loading ? `Loading · ${loaded} of 4 sources` : loaded === 4 ? 'Snapshot complete' : loaded ? 'Partial snapshot' : 'Snapshot unavailable';
  find('dashboard-state').textContent = summary;
  status.idle(`${summary} · Current domain · Read-only`);
  exportButton.disabled = loading || !loaded;
  refresh.disabled = loading;
  daysSelect.disabled = loading;
}

function renderIdentity() {
  if (loading && !domainDN) find('dashboard-context').replaceChildren(...placeholder(() => [bar('240px')]));
}

function render() {
  root.classList.toggle('is-loading-delayed', loadingDelayed);
  renderIdentity();
  renderInventory();
  renderEvidence();
  renderPolicy();
  renderSystems();
  renderTrusts();
  renderCollection();
}

async function load(fresh = false) {
  if (loading) return;
  loading = true;
  const finishLoading = beginLoading(root.querySelector('.dashboard__table'), { onDelay: () => { loadingDelayed = true; render(); } });
  data = {};
  failures = {};
  domainDN = '';
  filter.value = '';
  find('dashboard-time').textContent = '';
  find('dashboard-domain').textContent = 'Directory assessment';
  find('dashboard-domain-link').hidden = true;
  render();
  for (const source of Object.keys(sources)) {
    try {
      const result = await request(`dashboard/${source}?days=${days}${fresh ? '&fresh=1' : ''}`);
      if (!result?.root_dn || !result.collected_at) throw new Error('The server returned an incomplete dashboard response.');
      if (domainDN && domainDN !== result.root_dn.toLowerCase()) {
        data = {};
        throw new Error('The connected domain changed during collection. Refresh to collect a consistent snapshot.');
      }
      domainDN = result.root_dn.toLowerCase();
      data[source] = result;
      find('dashboard-domain').textContent = result.domain || result.root_dn;
      find('dashboard-context').textContent = `${result.root_dn}${result.dc ? ` · ${result.dc}` : ''}`;
      const domainLink = find('dashboard-domain-link');
      domainLink.href = objectLink({ dn: result.root_dn, name: result.domain }).href;
      domainLink.dataset.inspectDn = result.root_dn;
      domainLink.hidden = false;
      if (!selected) {
        const firstMatch = signals.find((signal) => data[signal.source]?.findings[signal.key]?.count > 0);
        if (firstMatch) { active = firstMatch; selected = true; }
      }
    } catch (failure) {
      failures[source] = failure.message;
      if (!Object.keys(data).length && domainDN) {
        find('dashboard-domain').textContent = 'Directory assessment';
        find('dashboard-domain-link').hidden = true;
        for (const key of Object.keys(sources)) failures[key] ??= 'Collection discarded because the connected domain changed. Refresh to retry.';
        break;
      }
    }
    render();
  }
  finishLoading();
  loadingDelayed = false;
  loading = false;
  const timestamps = Object.values(data).map((value) => value.collected_at).sort();
  if (timestamps.length) {
    const time = find('dashboard-time');
    time.dateTime = timestamps.at(-1);
    const collected = new Date(timestamps.at(-1));
    time.replaceChildren(
      element('span', '', new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(collected)),
      element('span', '', new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' }).format(collected)),
    );
  } else {
    find('dashboard-context').textContent = 'Directory data could not be collected. Check the session, then refresh.';
  }
  render();
}

filter.addEventListener('input', () => renderEvidence(true));
refresh.addEventListener('click', () => load(true));
daysSelect.addEventListener('change', () => {
  days = Number(daysSelect.value);
  try { localStorage.setItem(DAYS_KEY, String(days)); } catch { /* per-viewer convenience only */ }
  load();
});
exportButton.addEventListener('click', () => {
  const snapshot = {
    exported_at: new Date().toISOString(), scope: 'Current domain; objects visible to the connected session',
    limitations: 'Configuration signals are not proof of exploitability. Counts cover returned objects; evidence is capped at 100 objects per signal. Signals overlap. Missing attributes may reflect permissions.',
    inactive_days: days,
    signals: signals.map((signal) => ({ ...signal, label: fill(signal.label), description: fill(signal.description) })),
    sources: data, errors: failures,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = `powerview-dashboard-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

for (const tip of root.querySelectorAll('.dashboard__tip')) {
  tip.addEventListener('keydown', (event) => { if (event.key === 'Escape') tip.classList.add('is-dismissed'); });
  tip.addEventListener('mouseleave', () => tip.classList.remove('is-dismissed'));
  tip.addEventListener('focusout', () => tip.classList.remove('is-dismissed'));
}

load();
