import { attribute, objectType, recordName, values } from '../../core/directory.js';
import { accountDisabled, toTime } from '../../core/ldap-values.js';
import { button } from '../../core/dom.js';
import { confirmAction } from '../confirm.js';
import { notify } from '../notify.js';

const ACCOUNT_TYPES = new Set(['user', 'computer']);

export function createActions({ host, directory, scope, guard, canLeave, onChanged, onDeleted, isRoot = () => false, describeRemoval, extraActions }) {
  let current = null;

  async function run(label, perform, after) {
    if (!canLeave() || !guard.begin()) return;
    for (const control of host.querySelectorAll('button')) control.disabled = true;
    try {
      await perform();
    } catch (failure) {
      notify.error(failure.message);
      for (const control of host.querySelectorAll('button')) control.disabled = false;
      return;
    } finally {
      guard.end();
    }
    notify.success(label);
    try { await after(); } catch (failure) { notify.warn(`${label}, but refreshing failed: ${failure.message}`); }
  }

  function accountAction(action, label) {
    const record = current;
    return run(`${label} ${recordName(record)}`, () => directory.account(action, record.dn, scope(record.dn)), () => onChanged(record));
  }

  async function remove() {
    const record = current;
    if (!canLeave()) return;
    if (isRoot(record.dn)) {
      notify.error('Naming-context roots cannot be deleted.');
      return;
    }
    const confirmed = await confirmAction({
      title: `Delete ${recordName(record)}?`,
      context: record.dn,
      message: 'This permanently removes the object from the directory.',
      confirmLabel: 'Delete',
      danger: true,
      ...(describeRemoval?.(record) ?? {}),
    });
    if (!confirmed || isRoot(record.dn)) return;
    await run(`Deleted ${recordName(record)}`, () => directory.remove(record.dn, scope(record.dn)), () => onDeleted(record));
  }

  function action(label, iconName, handler, className = 'icon-button') {
    const control = button('', { iconName, className, ariaLabel: label });
    control.title = label;
    control.addEventListener('click', handler);
    return control;
  }

  return {
    render(record) {
      current = record;
      host.replaceChildren();
      if (!record) return;
      const type = objectType(record);
      if (ACCOUNT_TYPES.has(type)) {
        const control = attribute(record, 'userAccountControl');
        if (values(control).length) {
          const disabled = accountDisabled(control);
          host.append(disabled
            ? action('Enable account', 'check', () => accountAction('enable', 'Enabled'))
            : action('Disable account', 'ban', () => accountAction('disable', 'Disabled')));
        }
        if (toTime(attribute(record, 'lockoutTime')) !== null) {
          host.append(action('Unlock account', 'unlock', () => accountAction('unlock', 'Unlocked')));
        }
      }
      for (const extra of extraActions?.(record) ?? []) {
        host.append(action(extra.label, extra.iconName, () => { if (canLeave()) extra.run(record, () => onChanged(record)); }));
      }
      if (onDeleted && !isRoot(record.dn)) host.append(action('Delete object', 'trash', remove, 'icon-button panel-action--danger'));
    },
  };
}
