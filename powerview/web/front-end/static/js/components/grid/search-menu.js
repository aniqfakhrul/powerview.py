import { button, element } from '../../core/dom.js';

// Keys match Get-DomainUser's argparse options; the backend owns their semantics.
const OPTIONS = [
  ['enabled', 'Enabled accounts'], ['disabled', 'Disabled accounts'],
  ['passnotrequired', 'Password not required'], ['password_expired', 'Password expired'],
  ['preauthnotrequired', 'Kerberos preauthentication not required'], ['admincount', 'AdminCount = 1'],
  ['lockedout', 'Locked out'], ['spn', 'Has a service principal name'],
  ['allowdelegation', 'Allow delegation'], ['disallowdelegation', 'Disallow delegation'],
  ['trustedtoauth', 'Trusted to authenticate for delegation'], ['unconstrained', 'Unconstrained delegation'],
  ['rbcd', 'Resource-based constrained delegation'], ['shadowcred', 'Has key credentials'],
];
const EXCLUSIVE = { enabled: 'disabled', disabled: 'enabled', allowdelegation: 'disallowdelegation', disallowdelegation: 'allowdelegation' };
const ADVANCED_FIELDS = [
  ['identity', 'Identity', 'Name, distinguished name, or SID'],
  ['memberof', 'Member of', 'Group name or distinguished name'],
  ['department', 'Department', 'Department name'],
];

export function validateFilter(filter) {
  if (!filter) return '';
  if (!filter.startsWith('(') || !filter.endsWith(')')) return 'Wrap the LDAP filter in parentheses, for example (mail=*).';
  let depth = 0;
  for (let index = 0; index < filter.length; index += 1) {
    if (filter[index] === '\\') { index += 1; continue; }
    if (filter[index] === '(') depth += 1;
    if (filter[index] === ')') depth -= 1;
    if (depth < 0) return 'The LDAP filter has an unmatched closing parenthesis.';
  }
  return depth === 0 ? '' : 'The LDAP filter has an unmatched opening parenthesis.';
}

export function createSearchMenu({ trigger, menu, onApply, defaultBase, options = OPTIONS, exclusive = EXCLUSIVE, advancedFields = ADVANCED_FIELDS }) {
  const textKeys = ['base', 'filter', ...advancedFields.map(([key]) => key)];
  const emptySearch = () => ({ options: [], scope: 'SUBTREE', ...Object.fromEntries(textKeys.map((key) => [key, ''])) });
  let applied = emptySearch();
  let draft;
  const count = trigger.querySelector('[data-search-count]');

  function paint() {
    const total = applied.options.length + textKeys.filter((key) => applied[key]).length + Number(applied.scope !== 'SUBTREE');
    count.textContent = total ? String(total) : '';
    trigger.setAttribute('aria-label', total ? `Search options, ${total} active` : 'Search options');
    trigger.classList.toggle('is-active', total > 0);
  }

  function render() {
    const form = element('form', 'search-menu__form');
    form.append(element('p', 'search-menu__hint', 'Searches the directory when applied.'));
    const list = element('div', 'search-menu__options');
    list.hidden = !options.length;
    const boxes = new Map();
    for (const [key, label] of options) {
      const row = element('label', 'fields-menu__option');
      const box = element('input');
      box.type = 'checkbox';
      box.checked = draft.options.includes(key);
      box.addEventListener('change', () => {
        draft.options = draft.options.filter((item) => item !== key && (!box.checked || item !== exclusive[key]));
        if (box.checked) draft.options.push(key);
        if (box.checked && boxes.has(exclusive[key])) boxes.get(exclusive[key]).checked = false;
      });
      boxes.set(key, box);
      row.append(box, element('span', '', label));
      list.append(row);
    }
    form.append(list);
    const advanced = element('details', 'search-menu__advanced');
    advanced.open = !options.length || textKeys.some((key) => draft[key]) || draft.scope !== 'SUBTREE';
    advanced.append(element('summary', '', 'Advanced'));
    const fields = element('div', 'search-menu__fields');
    let filterInput;
    for (const [key, label, placeholder] of [
      ['base', 'Search base', defaultBase() || 'Domain root'],
      ...advancedFields,
      ['filter', 'LDAP filter', '(objectClass=*)'],
    ]) {
      const row = element('label', '', label);
      const input = element(key === 'filter' ? 'textarea' : 'input', 'text-input');
      input.value = draft[key];
      input.placeholder = placeholder;
      input.spellcheck = false;
      if (key === 'filter') input.rows = 2;
      input.addEventListener('input', () => { draft[key] = input.value.trim(); });
      if (key === 'filter') filterInput = input;
      row.append(input);
      fields.append(row);
    }
    const scopeLabel = element('label', '', 'Scope');
    const scope = element('select', 'text-input');
    scope.setAttribute('aria-label', 'Scope');
    for (const [value, label] of [['SUBTREE', 'Subtree'], ['LEVEL', 'One level'], ['BASE', 'Base object']]) {
      const option = element('option', '', label);
      option.value = value;
      scope.append(option);
    }
    scope.value = draft.scope;
    scope.addEventListener('change', () => { draft.scope = scope.value; });
    scopeLabel.append(scope);
    fields.prepend(scopeLabel);
    advanced.append(fields);
    form.append(advanced);
    const error = element('p', 'form-error');
    error.setAttribute('role', 'alert');
    error.hidden = true;
    form.append(error);
    const footer = element('div', 'fields-menu__footer');
    const clear = button('Clear', { className: 'link-button' });
    clear.addEventListener('click', () => { draft = emptySearch(); render(); menu.querySelector('input').focus(); });
    const apply = element('button', 'button button--primary', 'Apply');
    apply.type = 'submit';
    footer.append(clear, apply);
    form.append(footer);
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      const problem = validateFilter(draft.filter);
      error.textContent = problem;
      error.hidden = !problem;
      if (problem) {
        advanced.open = true;
        filterInput.focus();
        return;
      }
      applied = { ...draft, options: [...draft.options] };
      paint();
      menu.hidePopover();
      onApply(applied);
    });
    menu.replaceChildren(form);
  }

  function place() {
    const rect = trigger.getBoundingClientRect();
    const width = Math.min(360, innerWidth - 16);
    menu.style.width = `${width}px`;
    menu.style.left = `${Math.max(8, Math.min(rect.right - width, innerWidth - width - 8))}px`;
    menu.style.top = `${Math.min(rect.bottom + 6, innerHeight - 100)}px`;
    menu.style.maxHeight = `${Math.max(80, innerHeight - rect.bottom - 14)}px`;
  }
  menu.addEventListener('beforetoggle', (event) => {
    if (event.newState !== 'open') return;
    draft = { ...applied, options: [...applied.options] };
    render();
    place();
  });

  menu.addEventListener('toggle', (event) => {
    trigger.setAttribute('aria-expanded', String(event.newState === 'open'));
    if (event.newState === 'open') menu.querySelector('input').focus();
    else if (menu.contains(document.activeElement) || document.activeElement === document.body) trigger.focus();
  });
  window.addEventListener('resize', () => { if (menu.matches(':popover-open')) place(); });
  paint();
}
