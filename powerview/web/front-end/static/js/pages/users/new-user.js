import { assertPlainName } from '../../core/directory.js';
import { setBusy } from '../../core/dom.js';

export function createNewUser({ directory, defaultContainer, onCreated }) {
  const dialog = document.querySelector('#user-dialog');
  const form = document.querySelector('#user-form');
  const name = document.querySelector('#user-name');
  const password = document.querySelector('#user-password');
  const container = document.querySelector('#user-container');
  const error = document.querySelector('#user-error');
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#user-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const username = name.value;
    const basedn = container.value.trim();
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      assertPlainName(username);
      if (!password.value) throw new Error('Enter a password.');
      if (!basedn) throw new Error('Enter the container distinguished name.');
      await directory.create('user', username, password.value, basedn);
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    await onCreated(username, basedn);
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
