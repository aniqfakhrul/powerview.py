import { button, element } from '../../core/dom.js';
import { CATALOG, DEFAULT_KEYS, columnFor, isAttributeName } from './columns.js';

export function createFieldsMenu({ trigger, menu, getKeys, onApply }) {
  const label = trigger.querySelector('.fields-trigger__count');
  let draft = [];

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
    box.addEventListener('change', () => {
      draft = box.checked ? [...draft, column.key] : draft.filter((key) => key !== column.key);
    });
    row.append(box, element('span', '', column.label));
    if (column.custom) row.append(element('span', 'fields-menu__hint', 'attribute'));
    row.dataset.search = `${column.label} ${column.attributes.join(' ')}`.toLowerCase();
    return row;
  }

  function render() {
    const search = element('input', 'text-input');
    Object.assign(search, { type: 'search', placeholder: 'Find a field' });
    search.setAttribute('aria-label', 'Find a field');
    const list = element('div', 'fields-menu__list');
    const custom = draft.filter((key) => key.startsWith('attr:')).map(columnFor).filter(Boolean);
    list.append(...[...CATALOG, ...custom].map(option));
    search.addEventListener('input', () => {
      const query = search.value.trim().toLowerCase();
      for (const row of list.children) row.hidden = Boolean(query) && !row.dataset.search.includes(query);
    });

    const add = element('form', 'fields-menu__add');
    const attributeInput = element('input', 'text-input text-input--mono');
    Object.assign(attributeInput, { placeholder: 'LDAP attribute', spellcheck: false });
    attributeInput.setAttribute('aria-label', 'Add attribute column');
    const addButton = element('button', 'button', 'Add');
    addButton.type = 'submit';
    const error = element('p', 'form-error');
    error.hidden = true;
    add.append(attributeInput, addButton, error);
    add.addEventListener('submit', (event) => {
      event.preventDefault();
      const name = attributeInput.value.trim();
      const known = CATALOG.find((column) => column.attributes.some((attribute) => attribute.toLowerCase() === name.toLowerCase()));
      const key = known ? known.key : `attr:${name}`;
      if (!known && !isAttributeName(name)) { error.textContent = 'Enter an LDAP attribute name, such as telephoneNumber.'; error.hidden = false; return; }
      if (!draft.includes(key)) draft = [...draft, key];
      render();
      menu.querySelector('.fields-menu__add input')?.focus();
    });

    const footer = element('div', 'fields-menu__footer');
    const reset = button('Reset to default', { className: 'link-button' });
    reset.addEventListener('click', () => { draft = [...DEFAULT_KEYS]; render(); menu.querySelector('input[type="search"]').focus(); });
    const done = button('Done', { className: 'button button--primary' });
    done.addEventListener('click', () => menu.hidePopover());
    footer.append(reset, done);

    menu.replaceChildren(search, list, add, footer);
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
    render();
    place();
  });

  menu.addEventListener('toggle', (event) => {
    trigger.setAttribute('aria-expanded', String(event.newState === 'open'));
    if (event.newState === 'open') {
      menu.querySelector('input[type="search"]').focus();
      return;
    }
    if (!sameKeys(draft, getKeys())) onApply(draft);
    trigger.focus();
  });

  paintTrigger();
  return { refresh: paintTrigger };
}
