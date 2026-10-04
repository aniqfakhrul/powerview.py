import { element } from '../../core/dom.js';
import { bar, settle, skeletonItem, unavailable } from './dom.js';
import { count, numbers } from './format.js';

const find = (id) => document.getElementById(id);
const SEPARATOR = '\u00a0· ';
const known = (value, suffix = '') => (value == null ? 'Not readable' : `${numbers.format(value)}${suffix}`);

function duration(value, unit) {
  if (value == null) return 'Not readable';
  if (value === 'never' || value === 0 || value >= 922337203685) return 'No expiry';
  const amount = value / unit;
  return unit === 86400 ? count(amount, 'day') : count(amount, 'minute');
}

function inventoryDetail(key, counts) {
  const parts = key === 'cas'
    ? ['Forest-wide', counts.cas ? `${count(counts.published_templates, 'template')} published` : 'none registered']
    : [`${numbers.format(counts.enabled)} enabled`, `${numbers.format(counts.disabled)} disabled`, counts.unknown && `${numbers.format(counts.unknown)} unknown`].filter(Boolean);
  return parts.flatMap((part, index) => [...(index ? [SEPARATOR] : []), element('span', '', part)]);
}

function objectSkeleton(rows) {
  const list = element('div', 'dashboard__object-list');
  list.append(...Array.from({ length: rows }, () => {
    const detail = element('p');
    detail.append(bar('55%'));
    return skeletonItem('', bar('40%'), detail);
  }));
  return list;
}

export function renderInventory(view) {
  const host = find('dashboard-inventory');
  const inputs = ['users', 'computers', 'inventory'];
  settle(host, inputs.some((source) => view.waiting(source)), inputs.some((source) => view.data[source]));
  for (const key of ['users', 'computers', 'groups', 'ous', 'gpos', 'cas']) {
    const source = ['users', 'computers'].includes(key) ? key : 'inventory';
    const result = view.data[source];
    const value = result?.counts[source === 'inventory' ? key : 'total'];
    const total = host.querySelector(`[data-count="${key}"]`);
    const detail = host.querySelector(`[data-detail="${key}"]`);
    if (view.waiting(source) && !result) {
      total.replaceChildren(...view.placeholder(() => [bar('44px')]));
      detail?.replaceChildren(...view.placeholder(() => [bar('96px')]));
      continue;
    }
    total.textContent = value == null ? '—' : numbers.format(value);
    if (!detail) continue;
    if (value == null) detail.textContent = 'Unavailable';
    else detail.replaceChildren(...inventoryDetail(key, result.counts));
    detail.title = key === 'cas' && value == null ? result?.ca_error ?? '' : '';
  }
}

export function renderPolicy(view) {
  const host = find('dashboard-policy');
  const result = view.data.domain;
  if (settle(host, view.waiting('domain'), Boolean(result))) {
    host.replaceChildren(...view.placeholder(() => {
      const list = element('dl');
      list.append(...Array.from({ length: 9 }, (_, index) => skeletonItem('', bar(`${40 + (index * 13) % 30}%`), bar('48px'))));
      return [list];
    }));
    return;
  }
  if (!result) {
    host.replaceChildren(unavailable(view, 'domain', 'Domain policy unavailable.'));
    return;
  }
  const { policy } = result;
  const flags = policy.pwdProperties;
  const lockout = policy.lockoutThreshold === 0;
  const fields = [
    ['Minimum password length', known(policy.minPwdLength, ' characters')],
    ['Password history', known(policy.pwdHistoryLength, ' passwords')],
    ['Maximum password age', duration(policy.maxPwdAge, 86400)],
    ['Minimum password age', policy.minPwdAge === 0 ? '0 days' : duration(policy.minPwdAge, 86400)],
    ['Lockout threshold', lockout ? 'No lockout' : known(policy.lockoutThreshold, ' attempts')],
    ['Lockout duration', lockout ? 'Not applicable' : policy.lockoutDuration === 0 || policy.lockoutDuration === 'never' ? 'Until an administrator unlocks' : duration(policy.lockoutDuration, 60)],
    ['Password complexity', flags == null ? 'Not readable' : flags & 1 ? 'Required' : 'Not required'],
    ['Reversible encryption', flags == null ? 'Not readable' : flags & 16 ? 'Enabled' : 'Disabled'],
    ['Machine-account quota', known(policy['ms-DS-MachineAccountQuota'])],
  ];
  const list = element('dl');
  list.append(...fields.map(([label, value]) => {
    const row = element('div');
    row.append(element('dt', '', label), element('dd', '', value));
    return row;
  }));
  host.replaceChildren(list);
}

function renderSystems(view) {
  const result = view.data.computers;
  const systems = find('dashboard-systems');
  const controllers = find('dashboard-controllers');
  const waiting = view.waiting('computers');
  settle(controllers, waiting, Boolean(result));
  find('systems-total').textContent = result ? count(result.counts.total, 'computer') : '';
  find('controllers-total').textContent = result ? count(result.counts.controllers, 'controller') : '';
  if (settle(systems, waiting, Boolean(result))) {
    systems.replaceChildren(...view.placeholder(() => {
      const distribution = element('div', 'dashboard__distribution');
      distribution.append(...[62, 48, 40, 34, 26].map((width) => {
        const label = element('div', 'dashboard__bar-label');
        label.append(bar(`${width}%`), bar('24px'));
        return skeletonItem('', label, element('div', 'dashboard__bar'));
      }));
      return [distribution];
    }));
    controllers.replaceChildren(...view.placeholder(() => [objectSkeleton(2)]));
    return;
  }
  if (!result) {
    systems.replaceChildren(unavailable(view, 'computers', 'Computer inventory unavailable.'));
    controllers.replaceChildren(unavailable(view, 'computers', 'Computer inventory unavailable.'));
    return;
  }
  const { counts } = result;
  const items = result.systems.slice(0, 5);
  const other = result.systems.slice(5).reduce((sum, item) => sum + item.count, 0);
  if (other) items.push({ name: 'Other operating systems', count: other });
  const distribution = element('div', 'dashboard__distribution');
  distribution.append(...items.map((item) => {
    const row = element('div');
    const label = element('div', 'dashboard__bar-label');
    label.append(element('span', '', item.name), element('strong', '', numbers.format(item.count)));
    const track = element('div', 'dashboard__bar');
    track.setAttribute('aria-hidden', 'true');
    const fill = element('span');
    fill.style.width = `${counts.total ? item.count / counts.total * 100 : 0}%`;
    track.append(fill);
    row.append(label, track);
    return row;
  }));
  systems.replaceChildren(items.length ? distribution : element('p', 'dashboard__empty', 'No computers returned.'));
  if (counts.missing_logon) systems.append(element('p', 'dashboard__note', `${count(counts.missing_logon, 'enabled computer has', 'enabled computers have')} no readable replicated logon timestamp.`));
  const list = element('div', 'dashboard__object-list');
  list.append(...result.controllers.map((record) => {
    const row = element('div');
    row.append(view.links.object(record, record.host || record.name, 'computers'), element('p', '', `${record.os} · ${record.enabled ? 'Enabled' : 'Disabled'}`));
    return row;
  }));
  controllers.replaceChildren(result.controllers.length ? list : element('p', 'dashboard__empty', 'No domain controllers identified in returned account-control values.'));
  if (counts.controllers > result.controllers.length) controllers.append(element('p', 'dashboard__note', `Showing the first ${numbers.format(result.controllers.length)} of ${count(counts.controllers, 'controller')}.`));
}

function renderTrusts(view) {
  const result = view.data.inventory;
  const host = find('dashboard-trust-list');
  find('trusts-total').textContent = result ? count(result.counts.trusts, 'trust') : '';
  if (settle(host, view.waiting('inventory'), Boolean(result))) {
    host.replaceChildren(...view.placeholder(() => [objectSkeleton(2)]));
    return;
  }
  if (!result) {
    host.replaceChildren(unavailable(view, 'inventory', 'Trust inventory unavailable.'));
    return;
  }
  const list = element('div', 'dashboard__object-list');
  list.append(...result.trusts.map((record) => {
    const row = element('div');
    const direction = ['Disabled', 'Inbound · partner trusts this domain', 'Outbound · this domain trusts partner', 'Bidirectional'][record.direction] ?? 'Direction not readable';
    const flags = record.attributes;
    const scope = flags == null ? 'Attributes not readable' : flags & 32 ? 'Within forest' : flags & 8 ? 'Forest transitive' : 'Not marked forest transitive';
    row.append(view.links.object(record, record.partner || record.name), element('p', '', direction), element('p', '', scope));
    return row;
  }));
  host.replaceChildren(result.trusts.length ? list : element('p', 'dashboard__empty', 'No trust objects returned in this domain.'));
  if (result.counts.trusts > result.trusts.length) host.append(element('p', 'dashboard__note', `Showing the first ${numbers.format(result.trusts.length)} of ${count(result.counts.trusts, 'trust')}.`));
}

export function renderInfrastructure(view) {
  renderSystems(view);
  renderTrusts(view);
}
