import { createGridPage } from '../components/grid/grid-page.js';
import { notify } from '../components/notify.js';
import { groupColumns } from './groups/columns.js';
import { createNewGroup } from './groups/new-group.js';

const page = createGridPage({
  root: document.querySelector('#groups'),
  endpoint: 'get/domaingroup',
  noun: { singular: 'group', plural: 'groups' },
  columnSet: groupColumns,
  search: {
    options: [],
    advancedFields: [
      ['identity', 'Identity', 'Name, distinguished name, or SID'],
      ['memberidentity', 'Has member', 'Member name or distinguished name'],
    ],
  },
});

const newButton = document.querySelector('#group-new');
const newGroup = createNewGroup({
  directory: page.directory,
  defaultContainer: () => `CN=Users,${page.rootDN()}`,
  async onCreated(name, container) {
    notify.success(`Created ${name}`);
    await page.showCreated(`CN=${name},${container}`, name);
  },
});

newButton.addEventListener('click', () => newGroup.open());
page.domainReady.then((rootDN) => {
  newButton.disabled = !rootDN;
  if (!rootDN) newButton.title = 'Unavailable until the directory responds';
});
