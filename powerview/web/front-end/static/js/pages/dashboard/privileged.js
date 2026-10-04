import { skeletonRows } from '../../components/loading.js';
import { element, icon } from '../../core/dom.js';
import { check, choice, choiceGroup, remember, settle, unavailable } from './dom.js';
import { count, dateValue, moment, numbers, period } from './format.js';

const filters = [
  { key: 'all', label: 'All privileged accounts', count: 'accounts', description: 'User accounts in built-in privileged groups, including nested membership.', matches: () => true },
  { key: 'enabled', label: 'Enabled accounts', count: 'enabled', description: 'Privileged accounts that are not disabled.', matches: (account) => account.enabled },
  { key: 'unprotected', label: 'Not in Protected Users', count: 'unprotected', finding: true, protection: true, description: 'Enabled privileged accounts outside the Protected Users group, which blocks NTLM, delegation and long-lived credential caching for its members. Test service compatibility before adding accounts.', matches: (account) => account.enabled && !account.protected },
  { key: 'stale', label: 'Inactive > {days} days', count: 'stale', finding: true, description: 'Enabled privileged accounts whose replicated lastLogonTimestamp is more than {days} days old. Accounts that never signed in count from their last password change.', matches: (account) => account.stale },
  { key: 'old_password', label: 'Password > {age}', count: 'old_password', finding: true, description: 'Enabled privileged accounts whose password is older than {age} or has not been set.', matches: (account) => account.old_password },
  { key: 'never_expires', label: 'Password never expires', count: 'never_expires', finding: true, description: 'Enabled privileged accounts with DONT_EXPIRE_PASSWORD.', matches: (account) => account.enabled && account.never_expires },
];

export function createPrivilegedView(view) {
  const host = document.getElementById('dashboard-privileged');
  const total = document.getElementById('privileged-total');
  const requested = new URL(location.href).searchParams.get('accounts');
  let active = filters.some((item) => item.key === requested) || requested?.startsWith('group:') ? requested : 'all';
  choiceGroup(host);

  const fill = (text, result) => view.fill(text).replaceAll('{age}', period(result.password_age_days ?? 365));

  function select(key) {
    active = key;
    remember('accounts', key === 'all' ? '' : key);
    render({ selectionOnly: true });
    view.afterRender();
  }

  function filterChoice(definition, current, result) {
    if (definition.protection && !result.protected_users) {
      const item = choice('dashboard__signal', 'Protected Users group not found');
      item.control.disabled = true;
      item.value.textContent = '—';
      check(item.control, false);
      return item.control;
    }
    const item = choice('dashboard__signal', fill(definition.label, result));
    check(item.control, definition === current);
    item.control.dataset.filter = definition.key;
    item.control.dataset.matches = String(Boolean(definition.finding && result.counts[definition.count]));
    item.value.textContent = numbers.format(result.counts[definition.count]);
    item.control.addEventListener('click', () => select(definition.key));
    return item.control;
  }

  function aside(result, current) {
    const node = element('div', 'dashboard__signals dashboard__privileged-aside');
    node.setAttribute('role', 'radiogroup');
    node.setAttribute('aria-label', 'Privileged account views');
    const heading = element('h3', '', 'Accounts');
    heading.id = 'privileged-filters-title';
    const group = element('div', 'dashboard__choices');
    group.append(...filters.map((definition) => filterChoice(definition, current, result)));
    const members = element('ul', 'dashboard__privileged-groups');
    members.append(...result.groups.map((item) => {
      const row = element('li');
      const key = `group:${item.dn}`;
      const option = choice('dashboard__signal', item.name);
      check(option.control, current.key === key);
      option.control.dataset.filter = key;
      option.value.textContent = numbers.format(item.count);
      option.control.addEventListener('click', () => select(key));
      row.append(option.control);
      return row;
    }));
    node.append(heading, group, element('h3', '', 'Groups'), members);
    return node;
  }

  function about(text) {
    const tip = element('span', 'dashboard__tip dashboard__about');
    const info = element('button', 'icon-button dashboard__info');
    info.type = 'button';
    info.setAttribute('aria-label', 'About this filter');
    info.setAttribute('aria-describedby', 'privileged-description');
    info.append(icon('info'));
    const tooltip = element('span', 'dashboard__tooltip', text);
    tooltip.id = 'privileged-description';
    tooltip.setAttribute('role', 'tooltip');
    tip.append(info, tooltip);
    return tip;
  }

  function notes(account, result) {
    const node = element('span', 'dashboard__privileged-notes');
    const labels = [
      !account.enabled && 'Disabled', account.stale && 'Inactive', account.old_password && 'Old password',
      account.never_expires && 'Never expires', result.protected_users && account.enabled && !account.protected && 'Not in Protected Users',
    ].filter(Boolean);
    node.append(...labels.map((label) => element('span', label === 'Disabled' ? 'state state--disabled' : 'state state--outline', label)));
    return node;
  }

  function table(accounts, result) {
    const scroll = element('div', 'dashboard__privileged-accounts');
    scroll.tabIndex = 0;
    scroll.setAttribute('role', 'region');
    scroll.setAttribute('aria-label', 'Privileged accounts');
    const node = element('table', 'dashboard__table dashboard__privileged-table');
    const head = element('tr');
    head.append(...['Account', 'Groups', 'Last logon', 'Notes'].map((label) => Object.assign(element('th', '', label), { scope: 'col' })));
    const header = element('thead');
    header.append(head);
    const body = element('tbody');
    body.append(...accounts.map((account) => {
      const row = element('tr');
      const name = element('td');
      name.append(view.links.object(account, account.name, 'users'));
      const logon = element('td', '', dateValue(account.last_logon));
      if (account.last_logon) logon.title = moment(account.last_logon);
      const tags = element('td');
      tags.append(notes(account, result));
      row.append(name, element('td', '', account.groups.join(', ')), logon, tags);
      return row;
    }));
    node.append(header, body);
    scroll.append(node);
    return scroll;
  }

  function evidence(result, definition) {
    const accounts = definition.group ? definition.group.accounts : result.accounts.filter(definition.matches);
    const matches = definition.group ? definition.group.count : result.counts[definition.count];
    const section = element('section', 'dashboard__evidence');
    const heading = element('header', 'dashboard__evidence-heading');
    const title = element('h3', '', fill(definition.label, result));
    title.id = 'privileged-title';
    section.setAttribute('aria-labelledby', title.id);
    heading.append(title, about(fill(definition.description, result)));
    if (definition.group) {
      const details = view.links.object(definition.group, 'View group details', 'groups');
      details.className = 'dashboard__text-action';
      heading.append(details);
    }
    const footer = element('footer', 'dashboard__evidence-footer');
    footer.append(element('span', '', `${count(accounts.length, 'sampled account')} · ${count(matches, 'total match', 'total matches')}`));
    section.append(heading, accounts.length ? table(accounts, result) : element('p', 'dashboard__empty', 'No matching accounts in the returned sample.'), footer);
    return section;
  }

  function render({ selectionOnly = false } = {}) {
    const result = view.data.privileged;
    total.textContent = result ? numbers.format(result.counts.accounts) : '';
    if (settle(host, view.waiting('privileged'), Boolean(result))) {
      host.replaceChildren(...view.placeholder(() => {
        const node = element('table', 'dashboard__table dashboard__privileged-table');
        const body = element('tbody');
        body.append(...skeletonRows(['', '', '', ''], 5));
        node.append(body);
        return [node];
      }));
      return;
    }
    if (!result) {
      host.replaceChildren(unavailable(view, 'privileged', 'Privileged access unavailable.'));
      return;
    }
    const group = result.groups.find((item) => `group:${item.dn}` === active);
    const current = group
      ? { key: active, label: group.name, group, description: 'User members of this group, including nested membership. Sampled in name order.' }
      : filters.find((item) => item.key === active && !(item.protection && !result.protected_users)) ?? filters[0];
    const previous = host.querySelector('.dashboard__privileged-aside');
    if (selectionOnly && previous) {
      for (const control of previous.querySelectorAll('[role="radio"]')) check(control, control.dataset.filter === current.key);
      host.querySelector('.dashboard__evidence').replaceWith(evidence(result, current));
      return;
    }
    const scrollTop = previous?.scrollTop ?? 0;
    const focused = document.activeElement?.matches('#dashboard-privileged [role="radio"]');
    const layout = element('div', 'dashboard__privileged-body');
    const rail = aside(result, current);
    layout.append(rail, evidence(result, current));
    host.replaceChildren(layout);
    rail.scrollTop = scrollTop;
    if (focused) host.querySelector('[role="radio"][aria-checked="true"]')?.focus({ preventScroll: true });
  }

  return { render };
}
