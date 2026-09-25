import { createGridPage } from '../components/grid/grid-page.js';
import { renderSummary } from '../components/object-panel/summary.js';
import { notify } from '../components/notify.js';
import { gpoLinks, inheritanceBlocked, ouColumns, setGpoNames } from './ou/columns.js';
import { createNewOU } from './ou/new-ou.js';

function linkRows(record) {
  return [
    { label: 'Inheritance', values: [inheritanceBlocked(record) ? 'Blocked' : 'Inherited'] },
    ...gpoLinks(record).map((link, index) => ({
      label: `Link ${index + 1}`,
      values: [link.name, link.guid, link.enforced ? 'Enforced' : 'Not enforced', link.disabled ? 'Link disabled' : 'Link enabled'],
    })),
  ];
}

const page = createGridPage({
  root: document.querySelector('#ou'),
  endpoint: 'get/domainou',
  noun: { singular: 'organizational unit', plural: 'organizational units' },
  columnSet: ouColumns,
  search: {
    options: [['writable', 'Has delegated write access']],
    exclusive: {},
    advancedFields: [
      ['identity', 'Identity', 'Name or distinguished name'],
      ['gplink', 'Linked GPO', 'GPO GUID, for example 31B2F340'],
    ],
  },
  summary: { label: 'Policy', render: (panel, entry, record) => renderSummary(panel, linkRows(record)) },
  describeRemoval: () => ({ message: 'The OU must be empty, and an OU protected from accidental deletion cannot be deleted until that protection is removed.' }),
});

page.directory.gpoNames()
  .then((names) => { setGpoNames(names); page.rerender(); })
  .catch((failure) => notify.warn(`GPO names are unavailable, so linked GPOs show as GUIDs: ${failure.message}`));

const newButton = document.querySelector('#ou-new');
const newOU = createNewOU({
  directory: page.directory,
  defaultContainer: () => page.rootDN(),
  async onCreated(name, container, unprotected) {
    if (unprotected) notify.warn(`Created ${name}, but it could not be protected from accidental deletion. ${unprotected}`);
    else notify.success(`Created ${name}`);
    await page.showCreated(`OU=${name},${container}`, name);
  },
});

newButton.addEventListener('click', () => newOU.open());
page.domainReady.then((rootDN) => {
  newButton.disabled = !rootDN;
  if (!rootDN) newButton.title = 'Unavailable until the directory responds';
});
