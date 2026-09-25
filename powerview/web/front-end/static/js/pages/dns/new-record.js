import { setBusy } from '../../core/dom.js';

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const NODE_NAME = /^(?!\.)[A-Za-z0-9_.*-]+(?<!\.)$/;

export function createNewRecord({ directory, zone, onCreated }) {
  const dialog = document.querySelector('#dns-dialog');
  const form = document.querySelector('#dns-form');
  const zoneLabel = document.querySelector('#dns-dialog-zone');
  const name = document.querySelector('#dns-name');
  const address = document.querySelector('#dns-address');
  const error = document.querySelector('#dns-error');
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  document.querySelector('#dns-cancel').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    const target = zone();
    const recordName = name.value.trim();
    const recordAddress = address.value.trim();
    if (!NODE_NAME.test(recordName) || recordName === '@') { fail('Enter a host name such as web01, without the zone.'); name.focus(); return; }
    if (!IPV4.test(recordAddress)) { fail('Enter an IPv4 address such as 10.0.0.25.'); address.focus(); return; }
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      const created = await directory.dnsAddRecord({ zone: target, name: recordName, address: recordAddress });
      if (created !== true) throw new Error('The directory did not create the record. It may already exist; check the CLI logs.');
    } catch (failure) {
      fail(/already ?exists/i.test(failure.message)
        ? `${recordName}.${target} already exists. Delete it first or choose another name.`
        : failure.message);
      return;
    } finally {
      busy = false;
      setBusy(form, false);
    }
    dialog.close();
    await onCreated(recordName, target);
  });

  return {
    open() {
      form.reset();
      fail('');
      zoneLabel.textContent = zone();
      dialog.showModal();
      name.focus();
    },
  };
}
