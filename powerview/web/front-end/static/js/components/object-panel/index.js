import { createAttributes } from './attributes.js';
import { renderOverview } from './overview.js';
import { button, element } from '../../core/dom.js';

const TABS = [['overview', 'Overview'], ['attributes', 'Attributes']];

export function createObjectPanel({ root, defaultTab = 'overview', ...options }) {
  const attributes = createAttributes({ root, ...options, reopen: (dn, openOptions) => open(dn, openOptions) });
  const body = root.querySelector('[data-panel-body]');
  const filterHost = root.querySelector('[data-panel-filter-host]');
  const tabList = root.querySelector('[data-panel-tabs]');
  const overview = element('div', 'overview');
  overview.setAttribute('role', 'tabpanel');
  overview.tabIndex = -1;
  body.setAttribute('role', 'tabpanel');
  body.before(overview);
  const tabs = new Map();
  let active = defaultTab;
  let generation = 0;

  function show(name) {
    active = name;
    for (const [key, tab] of tabs) {
      const selected = key === name;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    }
    overview.hidden = name !== 'overview';
    body.hidden = name !== 'attributes';
    if (filterHost) filterHost.hidden = name !== 'attributes';
  }

  tabList.setAttribute('role', 'tablist');
  tabList.setAttribute('aria-label', 'Object details');
  for (const [key, label] of TABS) {
    const tab = button(label, { className: 'panel-tab' });
    tab.id = `${root.id}-tab-${key}`;
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', `${root.id}-${key}`);
    tab.addEventListener('click', () => { if (attributes.canLeave()) show(key); });
    tabs.set(key, tab);
    tabList.append(tab);
  }
  overview.id = `${root.id}-overview`;
  body.id = body.id || `${root.id}-attributes`;
  tabs.get('attributes').setAttribute('aria-controls', body.id);
  overview.setAttribute('aria-labelledby', tabs.get('overview').id);
  body.setAttribute('aria-labelledby', tabs.get('attributes').id);

  tabList.addEventListener('keydown', (event) => {
    const keys = [...tabs.keys()];
    const index = keys.indexOf(active);
    let next;
    if (event.key === 'ArrowRight') next = keys[(index + 1) % keys.length];
    else if (event.key === 'ArrowLeft') next = keys[(index - 1 + keys.length) % keys.length];
    else return;
    event.preventDefault();
    if (!attributes.canLeave()) return;
    show(next);
    tabs.get(next).focus();
  });

  function loading() {
    const box = element('div', 'skeleton');
    box.setAttribute('aria-hidden', 'true');
    for (let index = 0; index < 7; index += 1) box.append(element('span'));
    overview.replaceChildren(box);
  }

  function failed(dn) {
    const box = element('div', 'panel-message');
    const retry = button('Retry', { iconName: 'refresh' });
    retry.addEventListener('click', () => open(dn, { fresh: true }));
    box.append(element('h2', '', 'Cannot load this object'), element('p', '', 'The directory did not return this object. Retry, or check the Attributes tab for details.'), retry);
    overview.replaceChildren(box);
  }

  async function open(dn, openOptions = {}) {
    const current = ++generation;
    loading();
    const record = await attributes.open(dn, openOptions);
    if (current !== generation) return record;
    if (record) renderOverview(overview, record, options);
    else failed(dn);
    return record;
  }

  show(active);
  return { ...attributes, open, show };
}
