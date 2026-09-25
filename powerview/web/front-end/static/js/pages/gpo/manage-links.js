import { button, element, setBusy } from '../../core/dom.js';
import { linkState } from '../../core/gplink.js';
import { notify } from '../../components/notify.js';

export function createLinksDialog({ directory, targets, linksFor, onChanged, refreshTargets }) {
  const dialog = document.querySelector('#links-dialog');
  const form = document.querySelector('#links-form');
  const context = document.querySelector('#links-context');
  const list = document.querySelector('#links-list');
  const target = document.querySelector('#links-target');
  const enforced = document.querySelector('#links-enforced');
  const disabled = document.querySelector('#links-disabled');
  const error = document.querySelector('#links-error');
  let policy = null;
  let busy = false;

  function fail(message) {
    error.textContent = message;
    error.hidden = !message;
  }

  async function run(perform, success) {
    if (busy) return;
    busy = true;
    setBusy(form, true);
    fail('');
    try {
      const result = await perform();
      if (result !== true) throw new Error('PowerView did not confirm the change. Check the CLI logs.');
      notify.success(success);
      await onChanged();
    } catch (failure) {
      fail(failure.message);
    } finally {
      busy = false;
      setBusy(form, false);
      render();
    }
  }

  function render() {
    const selectedTarget = target.value;
    const links = linksFor(policy.guid);
    list.replaceChildren(...links.map((link) => {
      const item = element('li');
      const unlink = button('Unlink', { className: 'link-button' });
      unlink.addEventListener('click', () => run(() => directory.unlinkGpo({ guid: policy.guid, target: link.dn }), `Unlinked ${policy.name} from ${link.name}`));
      item.title = link.dn;
      item.append(element('span', 'links-list__name', link.name), element('span', 'links-list__state', linkState(link).join(', ') || 'enabled'), unlink);
      return item;
    }));
    if (!links.length) list.append(element('li', 'links-list__empty', 'Not linked anywhere'));
    const linked = new Set(links.map((link) => link.dn.toLowerCase()));
    const available = targets().filter((item) => !linked.has(item.dn.toLowerCase()));
    target.replaceChildren(...available.map((item) => new Option(`${item.name} — ${item.dn}`, item.dn)));
    if (available.some((item) => item.dn === selectedTarget)) target.value = selectedTarget;
    target.disabled = !available.length;
    form.querySelector('button[type="submit"]').disabled = !available.length;
  }

  document.querySelector('#links-close').addEventListener('click', () => { if (!busy) dialog.close(); });
  dialog.addEventListener('cancel', (event) => { if (busy) event.preventDefault(); });
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const option = target.selectedOptions[0];
    if (!option) return;
    const name = targets().find((item) => item.dn === option.value)?.name ?? option.value;
    run(() => directory.linkGpo({ guid: policy.guid, target: option.value, enabled: !disabled.checked, enforced: enforced.checked }), `Linked ${policy.name} to ${name}`);
  });

  return {
    open(next) {
      policy = next;
      form.reset();
      fail('');
      context.textContent = policy.name;
      render();
      dialog.showModal();
      refreshTargets().then(() => { if (dialog.open && !busy) render(); }).catch((failure) => fail(`Could not refresh link targets: ${failure.message}`));
    },
  };
}
