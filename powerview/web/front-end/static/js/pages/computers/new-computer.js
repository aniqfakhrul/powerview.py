import { assertPlainName } from '../../core/directory.js';
import { sameDN } from '../../core/dn.js';
import { setBusy } from '../../core/dom.js';

export function createNewComputer({ directory, defaultContainer, onCreated }) {
  const dialog = document.querySelector('#computer-dialog');
  const form = document.querySelector('#computer-form');
  const name = document.querySelector('#computer-name');
  const password = document.querySelector('#computer-password');
  const container = document.querySelector('#computer-container');
  const error = document.querySelector('#computer-error');
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#computer-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { password.value = ''; });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    // Accept either a host name or the computer account's trailing dollar sign.
    const computerName = name.value.replace(/\$$/, '');
    const basedn = container.value.trim();
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      assertPlainName(computerName);
      if (/[.$\s]/.test(computerName)) throw new Error('Enter a computer name without a domain suffix, spaces, or embedded dollar signs.');
      if (!password.value) throw new Error('Enter a password.');
      if (!basedn) throw new Error('Enter the container distinguished name.');
      if (!sameDN(basedn, defaultContainer())) {
        const connection = await directory.connection();
        if (!['LDAPS', 'ADWS'].includes(connection?.protocol?.toUpperCase())) {
          throw new Error('A custom container requires an LDAPS or ADWS connection. Use the default Computers container for this connection.');
        }
      }
      await directory.createComputer(computerName, password.value, basedn);
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    await onCreated(computerName);
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
