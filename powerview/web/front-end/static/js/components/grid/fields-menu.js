import { button, element } from '../../core/dom.js';
import { isAttributeName, literalLabel } from './columns.js';
import { matchSchema, renderSuggestions } from './schema-suggestions.js';

export function createFieldsMenu({ trigger, menu, columnSet, getKeys, onApply }) {
  const { catalog, defaults, columnFor } = columnSet;
  const label = trigger.querySelector('.fields-trigger__count');
  let draft = [];
  let widthsReset = false;
  const catalogAttributes = new Set([columnSet.name, ...catalog].flatMap((column) => column.attributes.map((name) => name.toLowerCase())));
  let refreshSearch = () => {};

  function sameKeys(a, b) {
    return a.length === b.length && a.every((key, index) => key === b[index]);
  }

  function paintTrigger() {
    const count = getKeys().length;
    label.textContent = String(count + 1);
    trigger.setAttribute('aria-label', `Fields, ${count + 1} shown`);
  }

  function option(column) {
    const row = element('label', 'fields-menu__option');
    const box = element('input');
    box.type = 'checkbox';
    box.checked = draft.includes(column.key);
    box.setAttribute('aria-label', column.hint ? `${column.label}, ${column.hint}` : column.label);
    box.addEventListener('change', () => {
      draft = box.checked ? [...draft, column.key] : draft.filter((key) => key !== column.key);
    });
    row.append(box, element('span', literalLabel(column) ? 'fields-menu__label' : 'fields-menu__label fields-menu__label--computed', column.label));
    if (column.hint) row.append(element('span', 'fields-menu__hint', column.hint));
    row.dataset.search = `${column.label} ${column.hint ?? ''} ${column.attributes.join(' ')}`.toLowerCase();
    return row;
  }

  function excludedFromSuggestions() {
    const chosen = draft.filter((key) => key.startsWith('attr:')).map((key) => key.slice(5).toLowerCase());
    return new Set([...catalogAttributes, ...chosen]);
  }

  function render(query = '') {
    const search = element('input', 'text-input');
    Object.assign(search, { type: 'search', placeholder: 'Find a field', value: query });
    search.setAttribute('aria-label', 'Find a field');
    const list = element('div', 'fields-menu__list');
    const custom = draft.filter((key) => key.startsWith('attr:')).map(columnFor).filter(Boolean);
    list.append(...[...catalog, ...custom].map(option));
    const suggestions = element('div', 'fields-menu__suggestions');
    const applySearch = () => {
      const text = search.value.trim().toLowerCase();
      for (const row of list.children) row.hidden = Boolean(text) && !row.dataset.search.includes(text);
      renderSuggestions(suggestions, {
        matches: matchSchema(columnSet.schemaAttributes(), text, excludedFromSuggestions()),
        objectClass: columnSet.objectClass,
        onPick(attribute) {
          draft = [...draft, `attr:${attribute.name}`];
          render(search.value);
          menu.querySelector('input[type="search"]').focus();
        },
      });
    };
    search.addEventListener('input', applySearch);
    refreshSearch = applySearch;

    const manual = element('details', 'fields-menu__manual');
    manual.hidden = columnSet.allowCustom === false;
    manual.append(element('summary', '', 'Add by exact name'));
    const add = element('form', 'fields-menu__add');
    const attributeInput = element('input', 'text-input text-input--mono');
    Object.assign(attributeInput, { placeholder: 'LDAP attribute', spellcheck: false });
    attributeInput.setAttribute('aria-label', 'Add attribute column');
    const addButton = element('button', 'button', 'Add');
    addButton.type = 'submit';
    const note = element('p', 'fields-menu__note');
    note.hidden = true;
    add.append(attributeInput, addButton, note);
    manual.append(add);
    let pendingOverride = '';
    attributeInput.addEventListener('input', () => {
      pendingOverride = '';
      addButton.textContent = 'Add';
      note.hidden = true;
    });
    const explain = (text, override) => {
      note.textContent = text;
      note.hidden = false;
      note.classList.toggle('form-error', !override);
      if (override) { pendingOverride = override; addButton.textContent = 'Add anyway'; }
    };
    add.addEventListener('submit', (event) => {
      event.preventDefault();
      const name = attributeInput.value.trim();
      const lower = name.toLowerCase();
      const columnsByLabel = [columnSet.name, ...catalog];
      const known = columnsByLabel.find((column) => column.label.toLowerCase() === lower)
        ?? columnsByLabel.find((column) => !column.request && column.attributes.some((attribute) => attribute.toLowerCase() === lower));
      if (known === columnSet.name) { explain(`${name} is already shown as the name column.`); return; }
      if (!known && !isAttributeName(name)) { explain('Enter an LDAP attribute name, for example description.'); return; }
      const schemaEntry = known ? null : columnSet.schemaAttribute(name);
      const confirmed = pendingOverride === name.toLowerCase();
      if (!known && !confirmed && columnSet.schemaAttributes() && !schemaEntry) {
        explain(`${name} isn't listed for ${columnSet.objectClass} in the schema. Constructed attributes are never listed and usually appear empty in grid searches.`, name.toLowerCase());
        return;
      }
      if (!confirmed && schemaEntry?.kind === 'binary') {
        explain(`${schemaEntry.name} is returned as raw bytes and may not be readable.`, name.toLowerCase());
        return;
      }
      const key = known ? known.key : `attr:${schemaEntry?.name ?? name}`;
      if (!draft.includes(key)) draft = [...draft, key];
      render();
      const input = menu.querySelector('.fields-menu__add input');
      input.closest('details').open = true;
      input.focus();
    });

    const footer = element('div', 'fields-menu__footer');
    const reset = button('Reset to default', { className: 'link-button' });
    reset.addEventListener('click', () => { draft = [...defaults]; widthsReset = true; render(); menu.querySelector('input[type="search"]').focus(); });
    const done = button('Done', { className: 'button button--primary' });
    done.addEventListener('click', () => menu.hidePopover());
    footer.append(reset, done);

    menu.replaceChildren(search, list, suggestions, manual, footer);
    applySearch();
  }

  function place() {
    const rect = trigger.getBoundingClientRect();
    const width = Math.min(300, window.innerWidth - 16);
    menu.style.width = `${width}px`;
    menu.style.top = `${rect.bottom + 6}px`;
    menu.style.left = `${Math.max(8, Math.min(rect.right - width, window.innerWidth - width - 8))}px`;
  }

  menu.addEventListener('beforetoggle', (event) => {
    if (event.newState !== 'open') return;
    draft = [...getKeys()];
    widthsReset = false;
    render();
    place();
  });

  menu.addEventListener('toggle', (event) => {
    trigger.setAttribute('aria-expanded', String(event.newState === 'open'));
    if (event.newState === 'open') {
      menu.querySelector('input[type="search"]').focus();
      return;
    }
    if (widthsReset || !sameKeys(draft, getKeys())) onApply(draft, { widthsReset });
    trigger.focus();
  });

  paintTrigger();
  return {
    refresh: paintTrigger,
    schemaChanged() { if (menu.matches(':popover-open')) refreshSearch(); },
  };
}
