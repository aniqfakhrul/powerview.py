import { accountKind, objectType, recordName } from '../../core/directory.js';
import { button, element, setBusy } from '../../core/dom.js';
import { leave } from '../../core/motion.js';
import { notify } from '../notify.js';

export function resetPassword({ record, directory, guard, onChanged }) {
  const returnFocus = document.activeElement;
  const type = accountKind(objectType(record));
  const dialog = element('dialog', 'dialog');
  dialog.setAttribute('aria-labelledby', 'reset-password-title');
  const form = element('form');
  const title = element('h2', 'dialog__title', type === 'computer' ? 'Reset computer account password' : 'Reset password');
  title.id = 'reset-password-title';
  const fields = element('div', 'dialog__fields');
  fields.append(element('p', '', recordName(record)), element('p', 'dialog__context', record.dn));
  if (type === 'computer') fields.append(element('p', '', 'Resetting this domain machine-account password may break the computer’s domain trust.'));

  function passwordField(label) {
    const wrapper = element('label', '', label);
    const input = element('input', 'text-input');
    input.type = 'password';
    input.autocomplete = 'new-password';
    input.required = true;
    wrapper.append(input);
    fields.append(wrapper);
    return input;
  }

  const password = passwordField('New password');
  const confirmation = passwordField('Confirm password');
  const visibility = element('label', 'dialog__check');
  const show = element('input');
  show.type = 'checkbox';
  show.addEventListener('change', () => {
    password.type = confirmation.type = show.checked ? 'text' : 'password';
  });
  visibility.append(show, 'Show passwords');
  fields.append(visibility);
  const error = element('p', 'form-error dialog__error');
  error.setAttribute('role', 'alert');
  error.hidden = true;
  const footer = element('footer', 'dialog__footer');
  const cancel = button('Cancel');
  const submit = button('Reset password', { className: 'button button--primary' });
  submit.type = 'submit';
  footer.append(cancel, submit);
  form.append(title, fields, error, footer);
  dialog.append(form);
  let busy = false;

  cancel.addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => {
    form.reset();
    leave(dialog);
    if (returnFocus?.isConnected) returnFocus.focus();
  }, { once: true });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    error.hidden = true;
    if (password.value !== confirmation.value) {
      error.textContent = 'Passwords do not match.';
      error.hidden = false;
      confirmation.focus();
      return;
    }
    if (!guard.begin()) return;
    busy = true;
    setBusy(form, true);
    try {
      await directory.resetPassword(type, record.dn, password.value);
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      return;
    } finally {
      busy = false;
      setBusy(form, false);
      guard.end();
    }
    form.reset();
    dialog.close();
    const label = `Password reset for ${recordName(record)}`;
    notify.success(label);
    try { await onChanged(); } catch (failure) { notify.warn(`${label}, but refreshing failed: ${failure.message}`); }
  });

  document.body.append(dialog);
  dialog.showModal();
  password.focus();
}
