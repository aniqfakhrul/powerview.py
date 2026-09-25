import { createGridPage } from '../components/grid/grid-page.js';
import { renderSummary } from '../components/object-panel/summary.js';
import { notify } from '../components/notify.js';
import { linkState } from '../core/gplink.js';
import { policyColumns, policyName, policyStatus } from './gpo/columns.js';
import { policyGuid, policyLinks, setLinkTargets } from './gpo/links.js';
import { createLinksDialog } from './gpo/manage-links.js';
import { createNewPolicy } from './gpo/new-gpo.js';
import { settingRows } from './gpo/settings.js';

let targets = [];
const settingsCache = new Map();

function settingsFor(guid) {
  const key = guid.toLowerCase();
  if (!settingsCache.has(key)) {
    settingsCache.set(key, page.directory.gpoSettings(guid).catch((failure) => {
      settingsCache.delete(key);
      throw failure;
    }));
  }
  return settingsCache.get(key);
}

function renderPolicy(panel, record) {
  const guid = policyGuid(record);
  const head = [
    { label: 'Status', values: [policyStatus(record)].filter(Boolean) },
    ...policyLinks(record).map((link, index) => ({ label: `Link ${index + 1}`, values: [link.name, link.dn, linkState(link).join(', ') || 'enabled'] })),
  ];
  renderSummary(panel, [...head, { label: 'Settings', values: ['Reading SYSVOL…'] }]);
  settingsFor(guid).then((settings) => {
    if (!panel.isConnected || policyGuid(record) !== guid) return;
    const rows = settingRows(settings);
    renderSummary(panel, [...head, ...(rows.length ? rows : [{ label: 'Settings', values: ['No configured settings found in SYSVOL'] }])]);
  }).catch((failure) => {
    if (panel.isConnected) renderSummary(panel, [...head, { label: 'Settings', values: [`Could not read SYSVOL: ${failure.message}`] }]);
  });
}

async function loadTargets(fresh = false) {
  const rootDN = await page.domainReady;
  if (!rootDN) return;
  targets = await page.directory.gpoLinkTargets(rootDN, { fresh });
  setLinkTargets(targets);
  page.rerender();
}

const page = createGridPage({
  root: document.querySelector('#gpo'),
  endpoint: 'get/domaingpo',
  noun: { singular: 'group policy', plural: 'group policies' },
  columnSet: policyColumns,
  deletable: false,
  search: {
    options: [],
    advancedFields: [['identity', 'Identity', 'Display name, GUID, or distinguished name']],
  },
  summary: { label: 'Policy', render: (panel, entry, record) => renderPolicy(panel, record) },
  panelActions: (record) => [{
    label: 'Manage links',
    iconName: 'ou',
    run: () => linksDialog.open({ guid: policyGuid(record), name: policyName(record) }),
  }],
});

const linksDialog = createLinksDialog({
  directory: page.directory,
  targets: () => targets,
  linksFor: (guid) => policyLinks({ attributes: { name: guid } }),
  onChanged: () => loadTargets(true),
  refreshTargets: () => loadTargets(true),
});

document.querySelector('#grid-refresh').addEventListener('click', () => {
  settingsCache.clear();
  loadTargets(true).catch((failure) => notify.warn(`Could not read where policies are linked: ${failure.message}`));
});

const newPolicy = createNewPolicy({
  directory: page.directory,
  targets: () => targets,
  async onCreated(name, linkto) {
    let linkProblem = '';
    if (linkto) {
      try {
        const matches = (await page.directory.list('get/domaingpo', { fresh: true, properties: ['name', 'displayName'], search: { identity: name } }))
          .filter((entry) => policyName(entry.record) === name);
        if (matches.length !== 1) throw new Error(matches.length ? 'More than one policy has this name; link it from Manage links.' : 'The new policy was not found.');
        const linked = await page.directory.linkGpo({ guid: policyGuid(matches[0].record), target: linkto, enabled: true, enforced: false });
        if (linked !== true) throw new Error('PowerView did not confirm the link.');
      } catch (failure) {
        linkProblem = failure.message;
      }
    }
    if (linkProblem) notify.warn(`Created ${name}, but it could not be linked. ${linkProblem}`);
    else notify.success(linkto ? `Created ${name} and linked it` : `Created ${name}`);
    await Promise.all([page.reloadAndFind(name), loadTargets(true)]);
  },
});

loadTargets().catch((failure) => notify.warn(`Could not read where policies are linked: ${failure.message}`));

const newButton = document.querySelector('#gpo-new');
newButton.addEventListener('click', () => newPolicy.open());
page.domainReady.then((rootDN) => {
  newButton.disabled = !rootDN;
  if (!rootDN) newButton.title = 'Unavailable until the directory responds';
});
