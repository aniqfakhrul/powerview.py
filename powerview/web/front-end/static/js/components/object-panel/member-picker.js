import { isDN } from '../../core/dn.js';
import { objectType, recordName } from '../../core/directory.js';
import { button, element, icon } from '../../core/dom.js';

const SEARCH_DELAY = 250;
const MIN_QUERY = 2;
const TYPE_ICONS = { user: 'user', group: 'group', computer: 'computer' };

export function createMemberPicker({ directory, groupsOnly, submitLabel, onSubmit, onCancel }) {
  const form = element('form', 'member-picker');
  const input = element('input', 'text-input');
  Object.assign(input, { placeholder: groupsOnly ? 'Group name or distinguished name' : 'Name or distinguished name', spellcheck: false, autocomplete: 'off' });
  input.setAttribute('aria-label', groupsOnly ? 'Group to add' : 'Member to add');
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-expanded', 'false');
  const suggestions = element('ul', 'member-picker__suggestions');
  suggestions.id = `member-picker-${Math.random().toString(36).slice(2)}`;
  suggestions.setAttribute('role', 'listbox');
  input.setAttribute('aria-controls', suggestions.id);
  const submit = element('button', 'button button--primary', submitLabel);
  submit.type = 'submit';
  const cancel = button('Cancel');
  const error = element('p', 'form-error');
  error.hidden = true;
  const controls = element('div', 'member-picker__controls');
  controls.append(cancel, submit);
  form.append(input, suggestions, error, controls);

  let chosen = null;
  let timer;
  let controller;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  function showSuggestions(records) {
    suggestions.replaceChildren(...records.map((record) => {
      const option = element('li', 'member-picker__option');
      option.setAttribute('role', 'option');
      option.tabIndex = -1;
      const type = objectType(record);
      option.append(icon(TYPE_ICONS[type] ?? 'object', `type--${type}`), element('span', '', recordName(record)), element('span', 'member-picker__dn', record.dn));
      option.addEventListener('click', () => choose(record));
      option.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); choose(record); } });
      return option;
    }));
    input.setAttribute('aria-expanded', String(records.length > 0));
  }

  function choose(record) {
    chosen = { dn: record.dn, label: recordName(record) };
    input.value = record.dn;
    showSuggestions([]);
    submit.focus();
  }

  input.addEventListener('input', () => {
    chosen = null;
    fail('');
    clearTimeout(timer);
    controller?.abort();
    const text = input.value.trim();
    if (text.length < MIN_QUERY || isDN(text)) { showSuggestions([]); return; }
    timer = setTimeout(async () => {
      controller = new AbortController();
      try {
        showSuggestions(await directory.findObjects(text, { groupsOnly, signal: controller.signal }));
      } catch (failure) {
        if (failure.name !== 'AbortError') showSuggestions([]);
      }
    }, SEARCH_DELAY);
  });

  input.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowDown' && suggestions.firstElementChild) { event.preventDefault(); suggestions.firstElementChild.focus(); }
  });
  suggestions.addEventListener('keydown', (event) => {
    const current = event.target.closest('[role="option"]');
    if (event.key === 'ArrowDown') { event.preventDefault(); current?.nextElementSibling?.focus(); }
    if (event.key === 'ArrowUp') { event.preventDefault(); (current?.previousElementSibling ?? input).focus(); }
  });
  form.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onCancel(); }
  });
  cancel.addEventListener('click', onCancel);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    const target = chosen ?? (isDN(text) ? { dn: text, label: text } : null);
    if (!target) { fail('Choose a suggestion or enter a full distinguished name.'); return; }
    fail('');
    for (const control of form.querySelectorAll('button, input')) control.disabled = true;
    const ok = await onSubmit(target, fail);
    if (!ok) for (const control of form.querySelectorAll('button, input')) control.disabled = false;
  });

  return {
    element: form,
    focus: () => input.focus(),
  };
}
