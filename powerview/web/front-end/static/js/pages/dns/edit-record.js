import { setBusy } from '../../core/dom.js';
import { IPV4 } from './new-record.js';

export function createEditRecord({ directory, onUpdated }) {
  const dialog = document.querySelector('#dns-edit-dialog');
  const form = document.querySelector('#dns-edit-form');
  const context = document.querySelector('#dns-edit-context');
  const current = document.querySelector('#dns-edit-current');
  const address = document.querySelector('#dns-edit-address');
  const error = document.querySelector('#dns-edit-error');
  let target = null;
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#dns-edit-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy || !target) return;
    const oldAddress = current.value;
    const newAddress = address.value.trim();
    if (!IPV4.test(newAddress)) { fail('Enter an IPv4 address such as 10.0.0.25.'); address.focus(); return; }
    if (newAddress === oldAddress) { fail('The new address is the same as the current one.'); address.focus(); return; }
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      const updated = await directory.dnsSetRecord({ zone: target.zone, dn: target.dn, oldAddress, address: newAddress });
      if (updated !== true) throw new Error('The directory did not update the record. Check the CLI logs.');
    } catch (failure) {
      fail(failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    await onUpdated(target, oldAddress, newAddress);
  });

  return {
    open({ dn, name, zone, addresses, refresh }) {
      target = { dn, name, zone, refresh };
      form.reset();
      fail('');
      context.textContent = `${name}.${zone}`;
      current.replaceChildren(...addresses.map((item) => new Option(item, item)));
      current.disabled = addresses.length < 2;
      dialog.showModal();
      address.focus();
    },
  };
}
