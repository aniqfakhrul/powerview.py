import { dnLabel } from '../../core/dn.js';
import { button, element, setBusy } from '../../core/dom.js';
import { attachObjectSearch } from '../object-search.js';
import { notify } from '../notify.js';

const RIGHTS = [
  ['fullcontrol', 'Full control', 'All permissions on the object.'],
  ['resetpassword', 'Reset password', 'The Reset Password extended right.'],
  ['writemembers', 'Read and write members', 'Read and write access to the member attribute.'],
  ['dcsync', 'Directory replication (DCSync)', 'Replicating Directory Changes and Replicating Directory Changes All. Intended for the domain object.'],
  ['immutable', 'Prevent deletion', 'Always denies Delete and Delete Tree for this principal.'],
  ['custom', 'Custom rights GUID', 'An object-specific extended right. The member attribute GUID uses read and write property access.'],
];
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function addACL({ dn, directory, guard, onChanged }) {
  const label = 'Add access entry';
  const success = 'Access entry added';
  const returnFocus = document.activeElement;
  const dialog = element('dialog', 'dialog acl-dialog');
  dialog.setAttribute('aria-labelledby', 'acl-editor-title');
  const form = element('form');
  const title = element('h2', 'dialog__title', label);
  title.id = 'acl-editor-title';
  const fields = element('div', 'dialog__fields');
  fields.append(element('p', '', dnLabel(dn)), element('p', 'dialog__context', dn));

  function field(label, control) {
    const row = element('label', '', label);
    control.setAttribute('aria-label', label);
    row.append(control);
    fields.append(row);
    return row;
  }

  function select(label, options) {
    const input = element('select', 'text-input');
    for (const [value, text] of options) {
      const option = element('option', '', text);
      option.value = value;
      input.append(option);
    }
    field(label, input);
    return input;
  }

  const principal = element('input', 'text-input');
  Object.assign(principal, { required: true, placeholder: 'Name, distinguished name, or SID', spellcheck: false });
  field('Principal', principal);
  const search = attachObjectSearch({ input: principal, directory, kind: 'principal', onChoose: () => rights.focus() });
  const rights = select('Rights', [['', 'Choose rights'], ...RIGHTS]);
  rights.required = true;
  const description = element('p', 'cell-muted');
  description.id = 'add-acl-description';
  rights.setAttribute('aria-describedby', description.id);
  fields.append(description);
  const guid = element('input', 'text-input');
  Object.assign(guid, { placeholder: '00000000-0000-0000-0000-000000000000', spellcheck: false });
  const guidField = field('Rights GUID', guid);
  const access = select('Access', [['allowed', 'Allow'], ['denied', 'Deny']]);
  const inheritance = select('Applies to', [['object', 'This object only'], ['descendants', 'This object and descendants']]);
  const inheritanceNote = element('p', 'cell-muted', 'Inheritance applies only where the directory permits it; protected objects may not inherit this entry.');
  fields.append(inheritanceNote);

  function sync() {
    description.textContent = RIGHTS.find(([key]) => key === rights.value)?.[2] ?? '';
    description.hidden = !description.textContent;
    guidField.hidden = rights.value !== 'custom';
    guid.required = !guidField.hidden;
    guid.disabled = guidField.hidden;
    access.disabled = rights.value === 'immutable';
    if (access.disabled) access.value = 'denied';
    inheritanceNote.hidden = inheritance.value !== 'descendants';
  }
  rights.addEventListener('change', sync);
  inheritance.addEventListener('change', sync);
  sync();

  const error = element('p', 'form-error dialog__error');
  error.setAttribute('role', 'alert');
  error.hidden = true;
  const footer = element('footer', 'dialog__footer');
  const cancel = button('Cancel');
  const submit = button('Add entry', { className: 'button button--primary' });
  submit.type = 'submit';
  footer.append(cancel, submit);
  form.append(title, fields, error, footer);
  dialog.append(form);
  let busy = false;

  cancel.addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => {
    search.close();
    dialog.remove();
    if (returnFocus?.isConnected) returnFocus.focus();
  }, { once: true });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    error.hidden = true;
    if (!principal.value.trim() || (rights.value === 'custom' && !GUID.test(guid.value.trim()))) {
      error.textContent = !principal.value.trim() ? 'Enter a principal.' : 'Enter a GUID in the form 00000000-0000-0000-0000-000000000000.';
      error.hidden = false;
      (!principal.value.trim() ? principal : guid).focus();
      return;
    }
    if (!guard.begin()) return;
    search.close();
    busy = true;
    setBusy(form, true);
    try {
      await directory.changeACL('add', dn, principal.value.trim(), {
        rights: rights.value === 'custom' ? 'fullcontrol' : rights.value,
        ...(rights.value === 'custom' ? { rights_guid: guid.value.trim().toLowerCase() } : {}),
        ace_type: access.value,
        inheritance: inheritance.value === 'descendants',
      });
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      return;
    } finally {
      busy = false;
      setBusy(form, false);
      sync();
      guard.end();
    }
    dialog.close();
    notify.success(success);
    try { await onChanged(); } catch (failure) { notify.warn(`${success}, but refreshing failed: ${failure.message}`); }
  });

  document.body.append(dialog);
  dialog.showModal();
  principal.focus();
}
