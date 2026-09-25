import { assertPlainName } from '../../core/directory.js';
import { setBusy } from '../../core/dom.js';

export function createNewGroup({ directory, defaultContainer, onCreated }) {
  const dialog = document.querySelector('#group-dialog');
  const form = document.querySelector('#group-form');
  const name = document.querySelector('#group-name');
  const container = document.querySelector('#group-container');
  const error = document.querySelector('#group-error');
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#group-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const groupName = name.value;
    const basedn = container.value.trim();
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      assertPlainName(groupName);
      if (!basedn) throw new Error('Enter the container distinguished name.');
      await directory.create('group', groupName, '', basedn);
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    await onCreated(groupName, basedn);
  });

  return {
    open() {
      form.reset();
      fail('');
      container.value = defaultContainer();
      dialog.showModal();
      name.focus();
    },
  };
}
