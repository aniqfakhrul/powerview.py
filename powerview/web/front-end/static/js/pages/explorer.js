import { createDirectory, isContainer, values } from '../core/directory.js';
import { namingContext, parentDN, sameDN } from '../core/dn.js';
import { createTree } from './explorer/tree.js';
import { createObjectPanel } from '../components/object-panel/index.js';
import { createDialogs } from './explorer/dialogs.js';
import { createStatus } from '../components/status.js';
import { createMutationGuard } from '../core/mutation-guard.js';
import { createResizer } from './explorer/resizer.js';
import { manageTreeOverlay } from './explorer/overlays.js';

const root = document.querySelector('#explorer');
const directory = createDirectory(new URL(root.dataset.apiRoot, window.location.origin));
const address = document.querySelector('#address');
const controls = {
  create: document.querySelector('#action-new'),
  move: document.querySelector('#action-move'),
  remove: document.querySelector('#action-delete'),
  refresh: document.querySelector('#action-refresh'),
};

let roots = [];
let activeDN = '';
let mutating = false;

const within = (dn, ancestor) => sameDN(dn, ancestor) || dn.toLowerCase().endsWith(`,${ancestor.toLowerCase()}`);
const scope = (dn) => namingContext(dn, roots);
const status = createStatus();
const guard = createMutationGuard({
  onBlocked: () => status.info('Wait for the current change to finish.'),
  onChange: (busy) => { mutating = busy; updateControls(); },
});

const tree = createTree({
  directory,
  onSelect(dn, { preview = false } = {}) {
    if (!properties.canLeave()) return false;
    if (!preview) navigate(dn, { fromTree: true });
    return true;
  },
});
const properties = createObjectPanel({
  root: document.querySelector('#object-pane'),
  defaultTab: 'attributes',
  directory, scope, status, guard,
  onNavigate: (dn) => go(dn),
  onSaved: () => navigate(activeDN, { fresh: true, fromTree: true }),
});
const dialogs = createDialogs({ directory, scope, guard, status, roots: () => roots, onChanged: changed });
const overlay = manageTreeOverlay(root, { toggle: document.querySelector('#tree-toggle'), closeButton: document.querySelector('#tree-close') });
createResizer(root, document.querySelector('#pane-resizer'), document.querySelector('#directory-pane'));

function updateControls() {
  const record = properties.current();
  const isRoot = Boolean(record) && roots.some((dn) => sameDN(dn, record.dn));
  controls.create.disabled = mutating || !record;
  controls.move.disabled = mutating || !record || isRoot;
  controls.remove.disabled = mutating || !record || isRoot;
  controls.refresh.disabled = mutating || !activeDN;
}

async function navigate(dn, { fresh = false, fromTree = false } = {}) {
  activeDN = dn;
  address.value = dn;
  overlay.close();
  if (!fromTree) tree.reveal(dn);
  updateControls();
  await properties.open(dn, { fresh });
  if (sameDN(activeDN, dn)) updateControls();
}

function go(dn) {
  if (!scope(dn)) { status.error('That distinguished name is outside the connected naming contexts.'); return; }
  if (properties.canLeave()) navigate(dn);
}

async function changed({ container, removed, movedTo } = {}) {
  await Promise.all([
    removed && tree.refresh(parentDN(removed)),
    container && tree.refresh(container),
  ]);
  if (movedTo) await navigate(movedTo, { fresh: true });
  else if (removed && within(activeDN, removed)) await navigate(parentDN(removed));
  else if (container) await tree.expand(container);
}

address.form.addEventListener('submit', (event) => {
  event.preventDefault();
  const dn = address.value.trim();
  if (dn && !sameDN(dn, activeDN)) go(dn);
  address.blur();
});
address.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') { address.value = activeDN; address.blur(); }
});

controls.create.addEventListener('click', () => {
  const record = properties.current();
  if (record && properties.canLeave()) dialogs.create(isContainer(record) ? record.dn : parentDN(record.dn));
});
controls.move.addEventListener('click', () => {
  const record = properties.current();
  if (record && properties.canLeave()) dialogs.move(record);
});
controls.remove.addEventListener('click', () => {
  const record = properties.current();
  if (record && properties.canLeave()) dialogs.remove(record);
});
controls.refresh.addEventListener('click', async () => {
  if (!properties.canLeave()) return;
  await Promise.all([tree.refresh(parentDN(activeDN)), tree.refresh(activeDN), navigate(activeDN, { fresh: true, fromTree: true })]);
});

async function initialize() {
  status.info('Connecting to the directory…');
  try {
    const domain = await directory.domain();
    if (typeof domain?.root_dn !== 'string' || !domain.root_dn) throw new Error('PowerView did not return a root DN. Check the connected session.');
    roots = [domain.root_dn];
    let warning = '';
    try {
      const server = await directory.server();
      const contexts = values(server?.raw?.namingContexts ?? server?.namingContexts).filter((dn) => typeof dn === 'string' && dn.includes('='));
      roots = [...new Map([...roots, ...contexts].map((dn) => [dn.toLowerCase(), dn])).values()];
    } catch (error) {
      warning = `Only the default naming context is shown: ${error.message}`;
    }
    tree.setRoots(roots);
    if (warning) status.error(warning); else status.clear();
    tree.expand(domain.root_dn);
    const requested = new URLSearchParams(window.location.search).get('dn');
    await navigate(requested && scope(requested) ? requested : domain.root_dn);
  } catch (error) {
    status.error('Not connected');
    properties.fail('Cannot connect to the directory', error, initialize);
  }
}

initialize();
