import { objectType } from '../../core/directory.js';
import { button, element } from '../../core/dom.js';
import { createAttributes } from './attributes.js';
import { membershipCount, renderMembership } from './membership.js';
import { createMembershipEditor } from './membership-actions.js';
import { createSecurity } from './security.js';
import { createActions } from './actions.js';

const TABS = [
  { key: 'attributes', label: 'Attributes' },
  { key: 'members', label: 'Members', attribute: 'member', noun: 'members', types: ['group'] },
  { key: 'memberOf', label: 'Member of', attribute: 'memberOf', noun: 'groups', types: ['group', 'user', 'computer'] },
  { key: 'security', label: 'Security', lazy: true },
];

export function createObjectPanel({ root, defaultTab = 'attributes', summary, ...options }) {
  const definitions = summary ? [TABS[0], { key: 'summary', label: summary.label }, ...TABS.slice(1)] : TABS;
  const attributes = createAttributes({ root, ...options, reopen: (dn, openOptions) => open(dn, openOptions) });
  const actionsHost = root.querySelector('[data-panel-actions]');
  const actions = actionsHost ? createActions({
    host: actionsHost,
    directory: options.directory,
    scope: options.scope,
    guard: options.guard,
    canLeave: () => attributes.canLeave(),
    onChanged: () => options.onSaved(),
    onDeleted: options.onDeleted,
    isRoot: options.isRoot,
    describeRemoval: options.describeRemoval,
  }) : null;
  const body = root.querySelector('[data-panel-body]');
  const filterHost = root.querySelector('[data-panel-filter-host]');
  const tabList = root.querySelector('[data-panel-tabs]');
  const tabs = new Map();
  let active = defaultTab;
  let preferred = defaultTab;
  let generation = 0;
  let currentDN = '';
  let securityDN = '';
  let securityFresh = false;
  const security = createSecurity(options);

  tabList.setAttribute('role', 'tablist');
  tabList.setAttribute('aria-label', 'Object details');
  body.id = body.id || `${root.id}-attributes`;

  for (const definition of definitions) {
    const tab = button('', { className: 'panel-tab' });
    tab.id = `${root.id}-tab-${definition.key}`;
    tab.setAttribute('role', 'tab');
    const label = element('span', '', definition.label);
    const count = element('span', 'panel-tab__count');
    tab.append(label, count);
    let panel = body;
    if (definition.key !== 'attributes') {
      panel = element('div', { security: 'security', summary: 'properties' }[definition.key] ?? 'membership');
      panel.id = `${root.id}-${definition.key}`;
      panel.tabIndex = -1;
      body.before(panel);
    }
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', tab.id);
    tab.setAttribute('aria-controls', panel.id);
    tab.addEventListener('click', () => { if (attributes.canLeave()) choose(definition.key); });
    tabs.set(definition.key, { definition, tab, panel, count });
    tabList.append(tab);
  }

  const available = () => [...tabs.values()].filter(({ tab }) => !tab.hidden).map(({ definition }) => definition.key);

  function show(key) {
    active = available().includes(key) ? key : defaultTab;
    for (const [name, { tab, panel }] of tabs) {
      const selected = name === active;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
      panel.hidden = !selected;
    }
    if (filterHost) filterHost.hidden = active !== 'attributes';
    if (active === 'security' && currentDN && securityDN !== currentDN) {
      securityDN = currentDN;
      security.render(tabs.get('security').panel, currentDN, { fresh: securityFresh });
    }
  }

  function choose(key) {
    preferred = key;
    show(key);
  }

  function applicable(record) {
    const type = record ? objectType(record) : null;
    for (const { definition, tab, count } of tabs.values()) {
      tab.hidden = Boolean(definition.types) && !definition.types.includes(type);
      count.textContent = definition.attribute && record ? String(membershipCount(record, definition.attribute)) : '';
      tab.setAttribute('aria-label', count.textContent ? `${definition.label} ${count.textContent}` : definition.label);
    }
  }

  tabList.addEventListener('keydown', (event) => {
    const keys = available();
    const index = keys.indexOf(active);
    let next;
    if (event.key === 'ArrowRight') next = keys[(index + 1) % keys.length];
    else if (event.key === 'ArrowLeft') next = keys[(index - 1 + keys.length) % keys.length];
    else if (event.key === 'Home') next = keys[0];
    else if (event.key === 'End') next = keys.at(-1);
    else return;
    event.preventDefault();
    if (!attributes.canLeave()) return;
    choose(next);
    tabs.get(next).tab.focus();
  });

  function placeholder(panel) {
    const box = element('div', 'skeleton');
    box.setAttribute('aria-hidden', 'true');
    for (let index = 0; index < 7; index += 1) box.append(element('span'));
    panel.replaceChildren(box);
  }

  function failed(panel, dn) {
    const box = element('div', 'panel-message');
    const retry = button('Retry', { iconName: 'refresh' });
    retry.addEventListener('click', () => open(dn, { fresh: true }));
    box.append(element('h2', '', 'Cannot load this object'), element('p', '', 'The directory did not return this object. Retry to load it again.'), retry);
    panel.replaceChildren(box);
  }

  async function open(dn, openOptions = {}) {
    const current = ++generation;
    currentDN = '';
    securityDN = '';
    actions?.render(null);
    securityFresh = Boolean(openOptions.fresh);
    security.cancel();
    const views = [...tabs.values()].filter(({ definition }) => definition.key !== 'attributes');
    for (const { panel } of views) placeholder(panel);
    const record = await attributes.open(dn, openOptions);
    if (current !== generation) return record;
    applicable(record);
    actions?.render(record);
    currentDN = record ? record.dn : '';
    for (const { definition, panel } of views) {
      if (!record) failed(panel, dn);
      else if (definition.key === 'summary') summary.render(panel, record.dn);
      else if (definition.lazy) panel.replaceChildren();
      else {
        const editor = createMembershipEditor({
          tab: definition.key,
          record,
          directory: options.directory,
          guard: options.guard,
          canLeave: () => attributes.canLeave(),
          onChanged: () => options.onSaved(),
        });
        renderMembership(panel, record, definition.attribute, { ...options, noun: definition.noun, editor });
      }
    }
    show(preferred);
    return record;
  }

  applicable(null);
  show(active);
  function refreshSummary() {
    if (summary && currentDN) summary.render(tabs.get('summary').panel, currentDN);
  }

  return { ...attributes, open, show: choose, refreshSummary, refreshActions: () => actions?.render(attributes.current()) };
}
