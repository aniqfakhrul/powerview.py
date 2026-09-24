import { button, element, icon } from '../../core/dom.js';

const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
const OWNER = /^(.*?)\s*\((S-[\d-]+)\)$/;

const inherited = (ace) => /INHERITED_ACE/.test(ace.ACEFlags ?? '');
const denied = (ace) => /DENIED/.test(ace.ACEType ?? '');
const clean = (value) => (value == null || value === 'None' ? '' : String(value));

function toEntry(ace) {
  return {
    denied: denied(ace),
    principal: clean(ace.SecurityIdentifier),
    rights: clean(ace.AccessMask || ace.ActiveDirectoryRights),
    appliesTo: clean(ace.ObjectAceType) || 'All properties',
    inheritedFrom: inherited(ace),
    inheritance: clean(ace.InheritanceType),
  };
}

function ownerBlock(owner) {
  const block = element('section', 'security__owner');
  block.append(element('h3', '', 'Owner'));
  const match = owner.match(OWNER);
  if (!owner) block.append(element('p', 'cell-muted', 'Not returned by the directory'));
  else if (match) block.append(element('p', '', match[1] || match[2]), element('code', '', match[2]));
  else block.append(element('p', '', owner));
  return block;
}

export function createSecurity({ directory }) {
  let controller;

  function table(entries) {
    const wrapper = element('section', 'security__acl');
    const toolbar = element('div', 'membership__toolbar');
    const search = element('label', 'search-field');
    const input = element('input');
    Object.assign(input, { type: 'search', placeholder: 'Filter entries' });
    input.setAttribute('aria-label', 'Filter access entries');
    search.append(icon('search'), input);
    const explicitOnly = element('label', 'security__toggle');
    const checkbox = element('input');
    checkbox.type = 'checkbox';
    explicitOnly.append(checkbox, document.createTextNode('Hide inherited'));
    const count = element('span', 'membership__count');
    toolbar.append(search, explicitOnly, count);

    const grid = element('table', 'security__table');
    const head = element('thead');
    const headRow = element('tr');
    for (const label of ['Access', 'Principal', 'Rights', 'Applies to', 'Source']) {
      const th = element('th', '', label);
      th.scope = 'col';
      headRow.append(th);
    }
    head.append(headRow);
    const body = element('tbody');
    grid.append(head, body);
    const scroller = element('div', 'security__scroll');
    scroller.append(grid);

    function update() {
      const query = input.value.trim().toLocaleLowerCase();
      const visible = entries.filter((entry) => (!checkbox.checked || !entry.inheritedFrom)
        && (!query || [entry.principal, entry.rights, entry.appliesTo].some((value) => value.toLocaleLowerCase().includes(query))));
      count.textContent = visible.length === entries.length ? String(entries.length) : `${visible.length} of ${entries.length}`;
      body.replaceChildren(...visible.map((entry) => {
        const tr = element('tr');
        const access = element('td');
        access.append(element('span', entry.denied ? 'state state--danger' : 'state state--neutral', entry.denied ? 'Deny' : 'Allow'));
        const principal = element('td', '', entry.principal);
        const rights = element('td', 'security__rights', entry.rights);
        const applies = element('td', '', entry.appliesTo);
        const source = element('td', 'cell-muted', entry.inheritedFrom ? 'Inherited' : 'Explicit');
        for (const cell of [principal, rights, applies]) cell.title = cell.textContent;
        tr.append(access, principal, rights, applies, source);
        return tr;
      }));
      if (!visible.length) {
        const tr = element('tr');
        const td = element('td', 'cell-muted', 'No entries match');
        td.colSpan = 5;
        tr.append(td);
        body.append(tr);
      }
    }

    input.addEventListener('input', update);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && input.value) { event.preventDefault(); input.value = ''; update(); }
    });
    checkbox.addEventListener('change', update);
    wrapper.append(toolbar, scroller);
    update();
    return wrapper;
  }

  return {
    async render(container, dn, { fresh = false } = {}) {
      controller?.abort();
      controller = new AbortController();
      const { signal } = controller;
      const skeleton = element('div', 'skeleton');
      skeleton.setAttribute('aria-hidden', 'true');
      for (let index = 0; index < 7; index += 1) skeleton.append(element('span'));
      container.replaceChildren(skeleton);
      try {
        const { owner, aces } = await directory.security(dn, { signal, fresh });
        if (signal.aborted) return;
        const entries = aces.map(toEntry).sort((a, b) => Number(a.inheritedFrom) - Number(b.inheritedFrom)
          || Number(b.denied) - Number(a.denied) || collator.compare(a.principal, b.principal));
        container.replaceChildren(ownerBlock(owner), table(entries));
      } catch (error) {
        if (signal.aborted) return;
        const box = element('div', 'panel-message');
        const retry = button('Retry', { iconName: 'refresh' });
        retry.addEventListener('click', () => this.render(container, dn, { fresh: true }));
        box.append(element('h2', '', 'Cannot read security'), element('p', '', error.message), retry);
        container.replaceChildren(box);
      }
    },
    cancel() { controller?.abort(); },
  };
}
