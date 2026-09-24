import { namingContext, parentDN, sameDN, splitDN } from '../../core/dn.js';
import { recordName } from '../../core/directory.js';
import { element, setBusy } from './dom.js';

const PLAIN_NAME = /^[^,=+<>;"\\\x00-\x1f]+$/;
const OBJECT_TYPES = [['user', 'User'], ['group', 'Group'], ['ou', 'Organizational unit']];

export function createDialogs({ directory, roots, scope, guard, status, onChanged }) {
  const dialog = document.querySelector('#object-dialog');
  const form = document.querySelector('#dialog-form');
  const fields = document.querySelector('#dialog-fields');
  const title = document.querySelector('#dialog-title');
  const submit = document.querySelector('#dialog-submit');
  const error = document.querySelector('#dialog-error');
  let action = null;

  const close = () => { if (!guard.busy()) dialog.close(); };
  document.querySelector('#dialog-cancel').addEventListener('click', close);
  dialog.addEventListener('cancel', (event) => { if (guard.busy()) event.preventDefault(); });
  dialog.addEventListener('close', () => { fields.replaceChildren(); action = null; });

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  function input(labelText, { type = 'text', value = '', autocomplete = 'off' } = {}) {
    const label = element('label', '', labelText);
    const control = element('input', 'text-input');
    Object.assign(control, { type, value, autocomplete, spellcheck: false });
    label.append(control);
    fields.append(label);
    return control;
  }

  function open({ heading, confirm, danger = false, context, run, after, success }) {
    fields.replaceChildren();
    fail('');
    title.textContent = heading;
    submit.textContent = confirm;
    submit.className = `button ${danger ? 'button--danger' : 'button--primary'}`;
    if (context) fields.append(element('p', 'dialog__context', context));
    action = { run, after, success };
    dialog.showModal();
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!action || !guard.begin()) return;
    const { run, after, success } = action;
    setBusy(form, true);
    fail('');
    try {
      await run();
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      guard.end();
      setBusy(form, false);
    }
    dialog.close();
    status.success(success);
    try { await after(); } catch (failure) { status.error(`${success}, but refreshing failed: ${failure.message}`); }
  });

  return {
    create(container) {
      open({ heading: 'New object', confirm: 'Create', context: container, success: 'Object created',
        run: () => {
          const name = nameInput.value;
          if (!PLAIN_NAME.test(name) || name.trim() !== name) throw new Error('Use a plain name without commas, equals signs, or leading and trailing spaces.');
          return directory.create(type.value, name, password.value, container);
        },
        after: () => onChanged({ container }),
      });
      const typeLabel = element('label', '', 'Type');
      const type = element('select', 'text-input');
      for (const [value, label] of OBJECT_TYPES) type.append(Object.assign(element('option', '', label), { value }));
      typeLabel.append(type);
      fields.append(typeLabel);
      const nameInput = input('Name');
      const password = input('Password', { type: 'password', autocomplete: 'new-password' });
      type.addEventListener('change', () => {
        password.parentElement.hidden = type.value !== 'user';
        if (type.value !== 'user') password.value = '';
      });
      nameInput.focus();
    },

    move(record) {
      const origin = parentDN(record.dn);
      open({ heading: `Move ${recordName(record)}`, confirm: 'Move', context: record.dn, success: `Moved ${recordName(record)}`,
        run: async () => {
          const target = destination.value.trim();
          if (sameDN(target, origin)) throw new Error('Choose a different container.');
          if (sameDN(target, record.dn) || target.toLowerCase().endsWith(`,${record.dn.toLowerCase()}`)) throw new Error('An object cannot be moved into itself.');
          if (!sameDN(namingContext(target, roots()) ?? '', scope(record.dn) ?? '')) throw new Error('Choose a container in the same naming context.');
          await directory.record(target, { fresh: true });
          await directory.move(record.dn, target, scope(record.dn));
        },
        after: () => {
          const target = destination.value.trim();
          return onChanged({ removed: record.dn, container: target, movedTo: `${splitDN(record.dn)[0]},${target}` });
        },
      });
      const destination = input('Destination container', { value: origin });
      destination.select();
    },

    remove(record) {
      open({ heading: `Delete ${recordName(record)}?`, confirm: 'Delete', danger: true, context: record.dn, success: `Deleted ${recordName(record)}`,
        run: () => directory.remove(record.dn, scope(record.dn)),
        after: () => onChanged({ removed: record.dn }),
      });
      fields.append(element('p', '', 'This permanently removes the object from the directory.'));
      submit.focus();
    },
  };
}
