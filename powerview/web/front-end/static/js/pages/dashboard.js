import { createAPI } from '../core/api.js';
import { button, element, icon } from '../core/dom.js';
import { createStatus } from '../components/status.js';
import { sources, signals } from './dashboard/signals.js';

const root = document.querySelector('#dashboard');
const request = createAPI(new URL(root.dataset.apiRoot, location.origin));
const status = createStatus();
const find = (id) => document.getElementById(id);
const format = new Intl.NumberFormat();
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
const displayDate = (value) => dateFormat.format(new Date(value));
const refresh = find('dashboard-refresh');
const exportButton = find('dashboard-export');
const filter = find('evidence-filter');
const signalButtons = new Map();
const pageSize = 20;
let data = {};
let failures = {};
let active = signals.find((signal) => signal.key === new URL(location.href).searchParams.get('signal')) ?? signals[0];
let selected = new URL(location.href).searchParams.has('signal');
let page = 0;
let loading = false;
let domainDN = '';

function objectLink(record, label = record.name) {
  if (!record.dn) return element('span', '', label);
  const link = element('a', 'dashboard__object', label);
  const url = new URL(root.dataset.explorer, location.origin);
  url.searchParams.set('dn', record.dn);
  link.href = url;
  link.title = record.dn;
  return link;
}

for (const [source, label] of [['users', 'Users'], ['computers', 'Computers']]) {
  find('dashboard-signals').append(element('h3', '', label));
  for (const signal of signals.filter((item) => item.source === source)) {
    const control = button('', { className: 'dashboard__signal' });
    const count = element('span', 'dashboard__signal-count', '—');
    control.append(element('span', '', signal.label), count);
    control.setAttribute('aria-controls', 'evidence-rows');
    control.addEventListener('click', () => {
      active = signal;
      selected = true;
      page = 0;
      filter.value = '';
      const url = new URL(location.href);
      url.searchParams.set('signal', signal.key);
      history.replaceState(null, '', url);
      renderEvidence();
    });
    signalButtons.set(signal.key, { control, count });
    find('dashboard-signals').append(control);
  }
}

function renderEvidence() {
  for (const signal of signals) {
    const result = data[signal.source]?.findings[signal.key];
    const { control, count } = signalButtons.get(signal.key);
    control.setAttribute('aria-pressed', String(signal.key === active.key));
    control.dataset.matches = String(Boolean(result?.count));
    count.textContent = result ? format.format(result.count) : '—';
    control.title = result ? `${format.format(result.count)} matching accounts` : failures[signal.source] ? 'Source unavailable' : 'Waiting for source';
  }
  find('evidence-title').textContent = active.label;
  find('evidence-description').textContent = active.description;
  const result = data[active.source]?.findings[active.key];
  filter.disabled = !result;
  const query = filter.value.trim().toLowerCase();
  const objects = (result?.objects ?? []).filter((record) => `${record.name} ${record.dn} ${record.evidence}`.toLowerCase().includes(query));
  const totalPages = Math.max(1, Math.ceil(objects.length / pageSize));
  page = Math.min(page, totalPages - 1);
  find('evidence-total').textContent = result ? `${format.format(result.count)} matches` : 'Not evaluated';
  find('evidence-page').textContent = result
    ? `${objects.length ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, objects.length)}` : '0'} of ${format.format(objects.length)} sampled${result.count > result.objects.length ? ` · first ${result.objects.length} of ${format.format(result.count)} matches` : ''}`
    : failures[active.source] ? 'Source unavailable · Refresh to retry' : 'Waiting for readable directory data';
  const rows = objects.slice(page * pageSize, (page + 1) * pageSize).map((record) => {
    const row = element('tr');
    const name = element('td');
    name.append(objectLink(record));
    const inspect = element('td');
    if (record.dn) {
      const link = objectLink(record, '');
      link.className = 'icon-button';
      link.setAttribute('aria-label', `Inspect ${record.name} in Explorer`);
      link.append(icon('open'));
      inspect.append(link);
    }
    row.append(name, element('td', '', record.evidence), inspect);
    return row;
  });
  find('evidence-rows').replaceChildren(...rows);
  const empty = find('evidence-empty');
  empty.hidden = rows.length > 0;
  empty.textContent = !result
    ? failures[active.source] ? `${sources[active.source]} could not be read. Refresh to retry; this signal has not been evaluated.` : `Waiting for ${sources[active.source].toLowerCase()}…`
    : result.count === 0 ? 'No matches in the returned directory data.' : 'No sampled objects match this filter.';
  find('evidence-prev').disabled = page === 0;
  find('evidence-next').disabled = page >= totalPages - 1;
}

function renderInventory() {
  for (const key of ['users', 'computers', 'groups', 'ous', 'gpos', 'trusts']) {
    const source = ['users', 'computers'].includes(key) ? key : 'inventory';
    const value = data[source]?.counts[source === 'inventory' ? key : 'total'];
    root.querySelector(`[data-count="${key}"]`).textContent = value == null ? '—' : format.format(value);
    root.querySelector(`[data-detail="${key}"]`).textContent = value == null
      ? failures[source] ? 'Unavailable' : 'Loading…'
      : source === 'inventory' ? 'Visible in this domain' : `${format.format(data[source].counts.enabled)} enabled · ${format.format(data[source].counts.disabled)} disabled${data[source].counts.unknown ? ` · ${format.format(data[source].counts.unknown)} unknown` : ''}`;
  }
}

const known = (value, suffix = '') => value == null ? 'Not readable' : `${format.format(value)}${suffix}`;
const duration = (value, unit) => {
  if (value == null) return 'Not readable';
  if (value === 0 || value >= 922337203685) return 'No expiry';
  const amount = value / unit;
  return `${format.format(amount)} ${unit === 86400 ? amount === 1 ? 'day' : 'days' : amount === 1 ? 'minute' : 'minutes'}`;
};

function renderPolicy() {
  const host = find('dashboard-policy');
  const result = data.domain;
  if (!result) {
    host.replaceChildren(element('p', 'dashboard__empty', failures.domain ? 'Domain policy unavailable. Refresh to retry.' : 'Reading domain policy…'));
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
    ['Lockout duration', policy.lockoutThreshold === 0 ? 'Not applicable' : policy.lockoutDuration === 0 ? 'Until unlocked' : duration(policy.lockoutDuration, 60)],
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
  if (!result) {
    const message = failures.computers ? 'Computer inventory unavailable. Refresh to retry.' : 'Reading computer inventory…';
    systems.replaceChildren(element('p', 'dashboard__empty', message));
    controllers.replaceChildren(element('p', 'dashboard__empty', message));
    find('systems-total').textContent = find('controllers-total').textContent = '';
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
    row.append(objectLink(record, record.host || record.name), element('p', '', `${record.os} · ${record.enabled ? 'Enabled' : 'Disabled'}`));
    list.append(row);
  }
  controllers.replaceChildren(result.controllers.length ? list : element('p', 'dashboard__empty', 'No domain controllers identified in returned account-control values.'));
  controllers.append(element('p', 'dashboard__note', counts.controllers > result.controllers.length ? `Showing the first ${result.controllers.length} of ${format.format(counts.controllers)} controllers.` : 'Identified from domain-controller account flags. Reachability and replication health are not tested.'));
}

function renderTrusts() {
  const result = data.inventory;
  const host = find('dashboard-trust-list');
  find('trusts-total').textContent = result ? format.format(result.counts.trusts) : '';
  if (!result) {
    host.replaceChildren(element('p', 'dashboard__empty', failures.inventory ? 'Trust inventory unavailable. Refresh to retry.' : 'Reading trust objects…'));
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
  find('dashboard-coverage-count').textContent = `${loaded} of 4 sources loaded`;
  status.idle(`${summary} · Current domain · Read-only`);
  const host = find('dashboard-sources');
  host.replaceChildren();
  for (const [source, label] of Object.entries(sources)) {
    const value = data[source];
    host.append(element('dt', '', label), element('dd', '', value ? `Collected ${displayDate(value.collected_at)}${value.counts?.missing_logon ? ` · ${format.format(value.counts.missing_logon)} enabled accounts without a readable replicated logon` : ''}` : failures[source] ? 'Unavailable' : 'Pending'));
  }
  exportButton.disabled = loading || !loaded;
  refresh.disabled = loading;
}

function render() {
  renderInventory();
  renderEvidence();
  renderPolicy();
  renderSystems();
  renderTrusts();
  renderCollection();
}

async function load() {
  if (loading) return;
  loading = true;
  data = {};
  failures = {};
  domainDN = '';
  page = 0;
  filter.value = '';
  find('dashboard-time').textContent = '';
  find('dashboard-domain').textContent = 'Directory assessment';
  find('dashboard-context').textContent = 'Reading the connected domain…';
  find('dashboard-domain-link').hidden = true;
  render();
  for (const source of Object.keys(sources)) {
    try {
      const result = await request(`dashboard/${source}`);
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

filter.addEventListener('input', () => { page = 0; renderEvidence(); });
find('evidence-prev').addEventListener('click', () => { page -= 1; renderEvidence(); });
find('evidence-next').addEventListener('click', () => { page += 1; renderEvidence(); });
refresh.addEventListener('click', load);
exportButton.addEventListener('click', () => {
  const snapshot = {
    exported_at: new Date().toISOString(), scope: 'Current domain; objects visible to the connected session',
    limitations: 'Configuration signals are not proof of exploitability. Counts cover returned objects; evidence is capped at 100 objects per signal. Signals overlap. Missing attributes may reflect permissions.',
    signals, sources: data, errors: failures,
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = `powerview-dashboard-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

load();
