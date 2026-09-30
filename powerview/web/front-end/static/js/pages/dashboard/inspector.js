import { createDirectory } from '../../core/directory.js';
import { createMutationGuard } from '../../core/mutation-guard.js';
import { createObjectPanel } from '../../components/object-panel/index.js';

export function createDashboardInspector({ root, status, getRootDN, onSaved }) {
  const directory = createDirectory(new URL(root.dataset.apiRoot, location.origin));
  const panelRoot = root.querySelector('#object-panel');
  const explorer = panelRoot.querySelector('#panel-explorer');
  const close = panelRoot.querySelector('#panel-close');
  const background = [...root.children].filter((node) => node !== panelRoot);
  const overlay = matchMedia('(max-width: 1100px)');
  let selectedDN = '';
  let returnFocus = null;
  const panel = createObjectPanel({
    root: panelRoot,
    directory,
    status,
    guard: createMutationGuard(),
    scope: (dn) => getRootDN() || dn,
    onNavigate: open,
    getRoots: async () => {
      const server = await directory.server();
      const roots = server?.raw?.namingContexts ?? server?.namingContexts;
      return Array.isArray(roots) ? roots : [];
    },
    onMoved: async ({ movedTo }) => {
      selectedDN = movedTo;
      const url = new URL(root.dataset.explorer, location.origin);
      url.searchParams.set('dn', movedTo);
      explorer.href = url;
      await panel.open(movedTo, { fresh: true });
      await onSaved();
    },
    onSaved: async () => {
      await panel.open(selectedDN, { fresh: true });
      await onSaved();
    },
  });

  function syncOverlay() {
    const covering = overlay.matches && !panelRoot.hidden;
    for (const node of background) node.inert = covering;
    if (covering && !panelRoot.contains(document.activeElement)) close.focus();
  }

  function open(dn) {
    if (!panel.canLeave()) return;
    if (!panelRoot.contains(document.activeElement)) returnFocus = document.activeElement;
    selectedDN = dn;
    const url = new URL(root.dataset.explorer, location.origin);
    url.searchParams.set('dn', dn);
    explorer.href = url;
    panelRoot.hidden = false;
    syncOverlay();
    close.focus();
    panel.open(dn);
  }

  function dismiss() {
    if (!panel.canLeave()) return;
    panelRoot.hidden = true;
    syncOverlay();
    if (returnFocus?.isConnected) returnFocus.focus({ preventScroll: true });
    else root.querySelector('#dashboard-refresh').focus();
  }

  root.addEventListener('click', (event) => {
    const link = event.target.closest('[data-inspect-dn]');
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    open(link.dataset.inspectDn);
  });
  close.addEventListener('click', dismiss);
  overlay.addEventListener('change', syncOverlay);
  explorer.addEventListener('click', (event) => { if (!panel.canLeave()) event.preventDefault(); });
  panelRoot.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !event.defaultPrevented) {
      event.preventDefault();
      dismiss();
    }
  });
}
