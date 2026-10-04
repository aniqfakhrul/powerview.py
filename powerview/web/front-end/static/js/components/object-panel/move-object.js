import { namingContext, parentDN, sameDN, splitDN } from '../../core/dn.js';
import { recordName } from '../../core/directory.js';
import { button, element, setBusy } from '../../core/dom.js';
import { leave } from '../../core/motion.js';
import { notify } from '../notify.js';

export function moveObject({ record, directory, guard, getRoots, onMoved }) {
  const returnFocus = document.activeElement;
  const origin = parentDN(record.dn);
  const dialog = element('dialog', 'dialog');
  dialog.setAttribute('aria-labelledby', 'move-object-title');
  const form = element('form');
  const title = element('h2', 'dialog__title', `Move ${recordName(record)}`);
  title.id = 'move-object-title';
  const fields = element('div', 'dialog__fields');
  fields.append(element('p', 'dialog__context', record.dn));
  const label = element('label', '', 'Destination container');
  const destination = element('input', 'text-input');
  Object.assign(destination, { value: origin, required: true, spellcheck: false });
  label.append(destination);
  fields.append(label, element('p', 'cell-muted', 'Enter the destination container DN. The object keeps its current name.'));
  const error = element('p', 'form-error dialog__error');
  error.setAttribute('role', 'alert');
  error.hidden = true;
  const footer = element('footer', 'dialog__footer');
  const cancel = button('Cancel');
  const submit = button('Move', { className: 'button button--primary' });
  submit.type = 'submit';
  footer.append(cancel, submit);
  form.append(title, fields, error, footer);
  dialog.append(form);
  let busy = false;

  cancel.addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => {
    leave(dialog);
    if (returnFocus?.isConnected) returnFocus.focus();
  }, { once: true });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy || !guard.begin()) return;
    const target = destination.value.trim();
    busy = true;
    setBusy(form, true);
    error.hidden = true;
    try {
      const roots = await getRoots();
      const source = namingContext(record.dn, roots);
      if (!source) throw new Error('Naming contexts are unavailable. Refresh the page before moving this object.');
      if (sameDN(record.dn, source)) throw new Error('Naming-context roots cannot be moved.');
      if (sameDN(target, origin)) throw new Error('Choose a different container.');
      if (sameDN(target, record.dn) || target.toLowerCase().endsWith(`,${record.dn.toLowerCase()}`)) throw new Error('An object cannot be moved into itself.');
      if (!sameDN(namingContext(target, roots) ?? '', source)) throw new Error('Choose a container in the same naming context.');
      await directory.record(target, { fresh: true });
      await directory.move(record.dn, target, source);
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      return;
    } finally {
      busy = false;
      setBusy(form, false);
      guard.end();
    }
    dialog.close();
    const success = `Moved ${recordName(record)}`;
    notify.success(success);
    try {
      await onMoved({ removed: record.dn, container: target, movedTo: `${splitDN(record.dn)[0]},${target}` });
    } catch (failure) { notify.warn(`${success}, but refreshing failed: ${failure.message}`); }
  });
  document.body.append(dialog);
  dialog.showModal();
  destination.select();
}
