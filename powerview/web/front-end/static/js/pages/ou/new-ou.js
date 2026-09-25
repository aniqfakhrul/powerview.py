import { assertPlainName } from '../../core/directory.js';
import { setBusy } from '../../core/dom.js';

export function createNewOU({ directory, defaultContainer, onCreated }) {
  const dialog = document.querySelector('#ou-dialog');
  const form = document.querySelector('#ou-form');
  const name = document.querySelector('#ou-name');
  const container = document.querySelector('#ou-container');
  const protect = document.querySelector('#ou-protect');
  const error = document.querySelector('#ou-error');
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#ou-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const ouName = name.value;
    const basedn = container.value.trim();
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      assertPlainName(ouName);
      if (!basedn) throw new Error('Enter the container distinguished name.');
      const created = await directory.create('ou', ouName, '', basedn);
      if (created !== true) throw new Error('The directory did not create the OU. It may already exist; check the CLI logs.');
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    let unprotected = '';
    if (protect.checked) {
      try {
        const protectedResult = await directory.protectFromDeletion(`OU=${ouName},${basedn}`);
        if (protectedResult !== true) unprotected = 'The directory did not confirm the change.';
      } catch (failure) {
        unprotected = failure.message;
      }
    }
    await onCreated(ouName, basedn, unprotected);
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
