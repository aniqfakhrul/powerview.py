import { removalParameters } from './acl-removal.js';
import { confirmAction } from '../confirm.js';
import { notify } from '../notify.js';
import { addACL } from './acl-editor.js';
import { beginLoading } from '../loading.js';
import { values } from '../../core/directory.js';
import { button, element, icon } from '../../core/dom.js';
import { chips, fitChips } from '../grid/chips.js';

const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
const OWNER = /^(.*?)\s*\((S-[\d-]+)\)$/;

const listed = (value) => values(value).filter((item) => item != null && item !== 'None').map(String);
const hasFlag = (ace, flag) => listed(ace.ACEFlags).includes(flag);
const denied = (ace) => /DENIED/.test(ace.ACEType ?? '');
const clean = (value) => (value == null || value === 'None' ? '' : String(value));

function scopeOf(ace) {
  const inheritable = hasFlag(ace, 'CONTAINER_INHERIT_ACE') || hasFlag(ace, 'OBJECT_INHERIT_ACE');
  const childrenOnly = hasFlag(ace, 'NO_PROPAGATE_INHERIT_ACE');
  let scope = 'This object';
  if (hasFlag(ace, 'INHERIT_ONLY_ACE')) scope = childrenOnly ? 'Child objects only' : 'Descendants only';
  else if (inheritable) scope = childrenOnly ? 'This object and children' : 'This object and descendants';
  const objectType = clean(ace.InheritanceType);
  return objectType && scope !== 'This object' ? `${scope} · ${objectType} objects` : scope;
}

function toEntry(ace) {
  return {
    removal: removalParameters(ace),
    denied: denied(ace),
    principal: clean(ace.SecurityIdentifier),
    rights: listed(ace.AccessMask).length ? listed(ace.AccessMask) : listed(ace.ActiveDirectoryRights),
    appliesTo: clean(ace.ObjectAceType) || 'All properties',
    scope: scopeOf(ace),
    inheritedFrom: hasFlag(ace, 'INHERITED_ACE'),
    type: clean(ace.ACEType),
    flags: listed(ace.ACEFlags),
  };
}

const pills = (items, tone = 'neutral') => {
  const list = element('span', 'security__pills');
  list.append(...items.map((item) => element('span', `state state--${tone}`, item)));
  return list;
};

function details(entry) {
  const list = element('dl', 'security__details');
  const rows = [
    ['Principal', entry.principal || 'Unknown principal'],
    ['Rights', entry.rights.length ? pills(entry.rights) : 'None'],
    ['Applies to', entry.appliesTo],
    ['Scope', entry.scope],
    ['Source', entry.inheritedFrom ? 'Inherited from a parent' : 'Explicit on this object'],
    ['Entry type', pills([entry.type], entry.denied ? 'danger' : 'success')],
    ['Flags', entry.flags.length ? pills(entry.flags) : 'None'],
  ];
  for (const [label, value] of rows) {
    const cell = element('dd');
    cell.append(value);
    list.append(element('dt', '', label), cell);
  }
  return list;
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

export function createSecurity({ directory, guard, canLeave, onSaved }) {
  let controller;

  let fitRights = () => {};
  const rightsWidth = new ResizeObserver(() => fitRights());

  async function removeEntry(entry, dn, remove) {
    if (!canLeave()) return;
    const confirmed = await confirmAction({
      title: 'Remove access entry?',
      context: dn,
      message: `${entry.denied ? 'Deny' : 'Allow'} · ${entry.principal} · ${entry.rights.join(', ')} · ${entry.appliesTo} · ${entry.scope}. Identical matching entries will also be removed.`,
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!confirmed || !canLeave() || !guard.begin()) return;
    remove.disabled = true;
    try {
      const { principalidentity, ...options } = entry.removal;
      await directory.changeACL('remove', dn, principalidentity, options);
    } catch (failure) {
      notify.error(failure.message);
      return;
    } finally {
      remove.disabled = false;
      guard.end();
    }
    notify.success('Access entry removed');
    try { await onSaved(); } catch (failure) { notify.warn(`Access entry removed, but refreshing failed: ${failure.message}`); }
  }

  function aceRows(entry, dn) {
    const row = element('tr', 'security__row');
    row.tabIndex = 0;
    row.setAttribute('aria-expanded', 'false');
    const access = element('td');
    access.append(element('span', entry.denied ? 'state state--danger' : 'state state--success', entry.denied ? 'Deny' : 'Allow'));
    const principal = element('td');
    const target = `${entry.appliesTo} · ${entry.scope}`;
    const name = element('span', 'security__principal', entry.principal || 'Unknown principal');
    name.title = entry.principal;
    const applies = element('span', 'security__target', target);
    applies.title = target;
    principal.append(name, applies);
    const rights = element('td');
    rights.append(chips(entry.rights));
    if (guard && entry.removal) {
      rights.classList.add('security__rights--removable');
      const remove = button('', { iconName: 'trash', className: 'icon-button security__remove', ariaLabel: `Remove access entry for ${entry.principal}` });
      remove.title = 'Remove access entry';
      remove.addEventListener('click', async (event) => {
        event.stopPropagation();
        await removeEntry(entry, dn, remove);
      });
      rights.append(remove);
    }
    row.append(access, principal, rights);
    const detailRow = element('tr', 'security__detail-row');
    detailRow.hidden = true;
    const detailCell = element('td');
    detailCell.colSpan = 3;
    detailCell.append(details(entry));
    detailRow.append(detailCell);
    const toggle = () => {
      detailRow.hidden = !detailRow.hidden;
      row.setAttribute('aria-expanded', String(!detailRow.hidden));
    };
    row.addEventListener('click', toggle);
    row.addEventListener('keydown', (event) => { if (event.target === row && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); toggle(); } });
    return [row, detailRow];
  }

  function groupRows(title, entries, dn) {
    if (!entries.length) return [];
    const row = element('tr', 'security__group');
    const heading = element('th', '', title);
    heading.scope = 'colgroup';
    heading.colSpan = 3;
    heading.append(element('span', 'membership__count', String(entries.length)));
    row.append(heading);
    return [row, ...entries.flatMap((entry) => aceRows(entry, dn))];
  }

  function aclList(entries, dn) {
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
    if (guard) {
      const add = button('', { iconName: 'plus', className: 'icon-button membership__add', ariaLabel: 'Add access entry' });
      add.title = 'Add access entry';
      add.addEventListener('click', () => {
        if (canLeave()) addACL({ dn, directory, guard, onChanged: onSaved });
      });
      toolbar.append(add);
    }

    const grid = element('table', 'security__table');
    const headRow = element('tr');
    const headers = ['Access', 'Principal', 'Rights'].map((label) => {
      const th = element('th', '', label);
      th.scope = 'col';
      return th;
    });
    headRow.append(...headers);
    const head = element('thead');
    head.append(headRow);
    const body = element('tbody');
    grid.append(head, body);
    rightsWidth.disconnect();
    fitRights = () => fitChips(body.querySelectorAll('.cell-chips'));
    rightsWidth.observe(headers[2]);

    function update() {
      const query = input.value.trim().toLocaleLowerCase();
      const visible = entries.filter((entry) => (!checkbox.checked || !entry.inheritedFrom)
        && (!query || [entry.principal, ...entry.rights, entry.appliesTo].some((value) => value.toLocaleLowerCase().includes(query))));
      count.textContent = visible.length === entries.length ? String(entries.length) : `${visible.length} of ${entries.length}`;
      body.replaceChildren(
        ...groupRows('Explicit', visible.filter((entry) => !entry.inheritedFrom), dn),
        ...groupRows('Inherited', visible.filter((entry) => entry.inheritedFrom), dn),
      );
      if (!visible.length) {
        const row = element('tr');
        const cell = element('td', 'cell-muted', 'No entries match');
        cell.colSpan = 3;
        row.append(cell);
        body.append(row);
      }
      if (grid.isConnected) fitRights();
    }

    input.addEventListener('input', update);
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && input.value) { event.preventDefault(); input.value = ''; update(); }
    });
    checkbox.addEventListener('change', update);
    wrapper.append(toolbar, grid);
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
      container.replaceChildren();
      const finishLoading = beginLoading(container, { signal, onDelay: () => container.replaceChildren(skeleton) });
      try {
        const { owner, aces } = await directory.security(dn, { signal, fresh });
        if (signal.aborted) return;
        const entries = aces.map(toEntry).sort((a, b) => Number(a.inheritedFrom) - Number(b.inheritedFrom)
          || Number(b.denied) - Number(a.denied) || collator.compare(a.principal, b.principal));
        container.replaceChildren(ownerBlock(owner), aclList(entries, dn));
      } catch (error) {
        if (signal.aborted) return;
        const box = element('div', 'panel-message');
        const retry = button('Retry', { iconName: 'refresh' });
        retry.addEventListener('click', () => this.render(container, dn, { fresh: true }));
        box.append(element('h2', '', 'Cannot read security'), element('p', '', error.message), retry);
        container.replaceChildren(box);
      } finally {
        if (!signal.aborted) finishLoading();
      }
    },
    cancel() { controller?.abort(); },
  };
}
