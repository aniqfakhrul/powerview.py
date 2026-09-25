import { setBusy } from '../../core/dom.js';

export function createNewPolicy({ directory, targets, onCreated }) {
  const dialog = document.querySelector('#gpo-dialog');
  const form = document.querySelector('#gpo-form');
  const name = document.querySelector('#gpo-name');
  const description = document.querySelector('#gpo-description');
  const linkto = document.querySelector('#gpo-linkto');
  const error = document.querySelector('#gpo-error');
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#gpo-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const policyName = name.value.trim();
    if (!policyName) { fail('Enter a name for the policy.'); name.focus(); return; }
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      const created = await directory.createGpo({ name: policyName, description: description.value.trim() });
      if (created !== true) throw new Error('The directory did not create the policy. Check the CLI logs.');
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    await onCreated(policyName, linkto.value);
  });

  return {
    open() {
      form.reset();
      fail('');
      linkto.replaceChildren(new Option('Don’t link', ''), ...targets().map((item) => new Option(`${item.name} — ${item.dn}`, item.dn)));
      dialog.showModal();
      name.focus();
    },
  };
}
