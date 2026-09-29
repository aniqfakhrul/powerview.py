import { recordName } from '../../core/directory.js';
import { isDN } from '../../core/dn.js';
import { button, element } from '../../core/dom.js';
import { attachObjectSearch } from '../object-search.js';

export function createMemberPicker({ directory, groupsOnly, submitLabel, onSubmit, onCancel }) {
  const form = element('form', 'member-picker');
  const input = element('input', 'text-input');
  Object.assign(input, { placeholder: groupsOnly ? 'Group name or distinguished name' : 'Name or distinguished name', spellcheck: false });
  input.setAttribute('aria-label', groupsOnly ? 'Group to add' : 'Member to add');
  const submit = element('button', 'button button--primary', submitLabel);
  submit.type = 'submit';
  const cancel = button('Cancel');
  const error = element('p', 'form-error');
  error.hidden = true;
  const controls = element('div', 'member-picker__controls');
  controls.append(cancel, submit);
  form.append(input, error, controls);

  let chosen = null;
  let submitting = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  const search = attachObjectSearch({
    input,
    directory,
    kind: groupsOnly ? 'group' : 'member',
    onChoose(record) {
      chosen = { dn: record.dn, label: recordName(record) };
      submit.focus();
    },
  });

  input.addEventListener('input', () => {
    chosen = null;
    fail('');
  });
  form.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    if (!submitting) onCancel();
  });
  cancel.addEventListener('click', () => { if (!submitting) onCancel(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    const target = chosen ?? (isDN(text) ? { dn: text, label: text } : null);
    if (!target) { fail('Choose a suggestion or enter a full distinguished name.'); return; }
    fail('');
    search.close();
    submitting = true;
    form.setAttribute('aria-busy', 'true');
    for (const control of form.querySelectorAll('button, input')) control.disabled = true;
    const ok = await onSubmit(target, fail);
    submitting = false;
    form.setAttribute('aria-busy', 'false');
    if (!ok) {
      for (const control of form.querySelectorAll('button, input')) control.disabled = false;
      input.focus();
    }
  });

  return {
    element: form,
    busy: () => submitting,
    focus: () => input.focus(),
  };
}
