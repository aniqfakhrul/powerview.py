import { removalParameters } from './acl-removal.js';
import { dnLabel } from '../../core/dn.js';
import { button, element, setBusy } from '../../core/dom.js';
import { leave } from '../../core/motion.js';
import { notify } from '../notify.js';

const TYPES = new Set(['ACCESS_ALLOWED_ACE', 'ACCESS_DENIED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE', 'ACCESS_DENIED_OBJECT_ACE']);
const FLAGS = [[1, 'Object inherit'], [2, 'Container inherit'], [4, 'Immediate children only'], [8, 'Descendants only']];
const PERMISSIONS = [
  [0x1, 'Create child'], [0x2, 'Delete child'], [0x4, 'List children'], [0x8, 'Validated write'],
  [0x10, 'Read property'], [0x20, 'Write property'], [0x40, 'Delete tree'], [0x80, 'List object'],
  [0x100, 'Extended right'], [0x10000, 'Delete'], [0x20000, 'Read permissions'], [0x40000, 'Write DACL'],
  [0x80000, 'Write owner'], [0x100000, 'Synchronize'], [0x10000000, 'Generic all'], [0x20000000, 'Generic execute'],
  [0x40000000, 'Generic write'], [0x80000000, 'Generic read'],
];
const hex = (value) => `0x${value.toString(16).padStart(8, '0')}`;
const parseMask = (value) => /^(0x[\da-f]{1,8}|\d+)$/i.test(value.trim()) ? Number(value) : NaN;
const validMask = (value) => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;

export function canEditACE(ace) {
  return Boolean(removalParameters(ace)) && TYPES.has(ace.ACEType) && validMask(ace.AccessMaskValue)
    && Number.isInteger(ace.ACEFlagsValue) && ace.ACEFlagsValue >= 0 && ace.ACEFlagsValue <= 255 && !(ace.ACEFlagsValue & 16);
}

export function editACL({ dn, ace, directory, guard, onChanged }) {
  if (!canEditACE(ace)) return;
  const returnFocus = document.activeElement;
  const dialog = element('dialog', 'dialog acl-dialog');
  dialog.setAttribute('aria-labelledby', 'edit-acl-title');
  const form = element('form');
  const title = element('h2', 'dialog__title', 'Edit access entry');
  title.id = 'edit-acl-title';
  const fields = element('div', 'dialog__fields');
  fields.append(element('p', '', dnLabel(dn)), element('p', 'dialog__context', dn));
  const field = (label, control) => {
    const row = element('label', '', label);
    control.setAttribute('aria-label', label);
    row.append(control);
    fields.append(row);
  };
  const principal = element('input', 'text-input');
  principal.value = ace.SecurityIdentifier || ace.RawSecurityIdentifier;
  principal.readOnly = true;
  field('Principal', principal);
  const access = element('select', 'text-input');
  for (const [value, text] of [['allowed', 'Allow'], ['denied', 'Deny']]) {
    const option = element('option', '', text);
    option.value = value;
    access.append(option);
  }
  access.value = ace.ACEType.includes('DENIED') ? 'denied' : 'allowed';
  field('Access', access);
  const mask = element('input', 'text-input');
  mask.value = hex(ace.AccessMaskValue);
  mask.spellcheck = false;
  mask.required = true;
  field('Access mask', mask);
  const permissions = element('details', 'acl-edit__permissions');
  permissions.append(element('summary', '', 'Permission bits'));
  const permissionGrid = element('div', 'acl-edit__checks');
  const checks = PERMISSIONS.map(([bit, label]) => {
    const row = element('label');
    const input = element('input');
    input.type = 'checkbox';
    row.append(input, document.createTextNode(label));
    permissionGrid.append(row);
    input.addEventListener('change', () => {
      const current = parseMask(mask.value);
      if (!validMask(current)) return;
      mask.value = hex((input.checked ? current | bit : current & ~bit) >>> 0);
    });
    return { bit, input };
  });
  const syncMask = () => {
    const value = parseMask(mask.value);
    for (const { bit, input } of checks) {
      input.disabled = !validMask(value);
      input.checked = validMask(value) && Boolean(value & bit);
    }
  };
  mask.addEventListener('input', syncMask);
  syncMask();
  permissions.append(permissionGrid);
  fields.append(permissions);
  const scope = element('fieldset', 'acl-edit__scope');
  scope.append(element('legend', '', 'Inheritance'));
  const flags = FLAGS.map(([bit, label]) => {
    const row = element('label');
    const input = element('input');
    input.type = 'checkbox';
    input.checked = Boolean(ace.ACEFlagsValue & bit);
    row.append(input, document.createTextNode(label));
    scope.append(row);
    return { bit, input };
  });
  fields.append(scope);
  for (const [label, value] of [['Object-specific right', ace.ObjectAceTypeGuid], ['Inherited object type', ace.InheritanceType]]) {
    if (value && value !== 'None') fields.append(element('p', 'dialog__context', `${label}: ${value}`));
  }
  const error = element('p', 'form-error dialog__error');
  error.setAttribute('role', 'alert');
  error.hidden = true;
  const footer = element('footer', 'dialog__footer');
  const cancel = button('Cancel');
  const save = button('Save changes', { className: 'button button--primary' });
  save.type = 'submit';
  footer.append(cancel, save);
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
    if (busy) return;
    error.hidden = true;
    const value = parseMask(mask.value);
    if (!validMask(value)) {
      error.textContent = 'Enter a mask from 0 to 0xffffffff, in decimal or hexadecimal.';
      error.hidden = false;
      mask.focus();
      return;
    }
    if (!guard.begin()) return;
    busy = true;
    setBusy(form, true);
    try {
      await directory.editACE(dn, removalParameters(ace).ace, {
        access_mask: value,
        ace_type: access.value,
        ace_flags: flags.reduce((value, { bit, input }) => value | (input.checked ? bit : 0), 0),
      });
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      return;
    } finally {
      busy = false;
      setBusy(form, false);
      syncMask();
      guard.end();
    }
    dialog.close();
    notify.success('Access entry updated');
    try { await onChanged(); } catch (failure) { notify.warn(`Access entry updated, but refreshing failed: ${failure.message}`); }
  });
  document.body.append(dialog);
  dialog.showModal();
  access.focus();
}
