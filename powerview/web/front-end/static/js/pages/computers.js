import { createGridPage } from '../components/grid/grid-page.js';
import { notify } from '../components/notify.js';
import { createNewComputer } from './computers/new-computer.js';
import { computerColumns } from './computers/columns.js';

const page = createGridPage({
  root: document.querySelector('#computers'),
  endpoint: 'get/domaincomputer',
  noun: { singular: 'computer', plural: 'computers' },
  columnSet: computerColumns,
  search: {
    options: [
      ['enabled', 'Enabled computers'],
      ['disabled', 'Disabled computers'],
      ['workstation', 'Workstations'],
      ['notworkstation', 'Servers'],
      ['excludedcs', 'Exclude domain controllers'],
      ['obsolete', 'Obsolete operating systems'],
      ['spn', 'Has a service principal name'],
      ['unconstrained', 'Unconstrained delegation'],
      ['trustedtoauth', 'Constrained delegation'],
      ['rbcd', 'Resource-based constrained delegation'],
      ['shadowcred', 'Has key credentials'],
      ['laps', 'LAPS'],
      ['pre2k', 'Pre-created Windows 2000 accounts'],
    ],
    exclusive: {
      enabled: 'disabled', disabled: 'enabled',
      workstation: 'notworkstation', notworkstation: 'workstation',
    },
    advancedFields: [['identity', 'Identity', 'Name, DNS host name, or SID']],
  },
});

const addButton = document.querySelector('#computer-new');
const newComputer = createNewComputer({
  directory: page.directory,
  defaultContainer: () => `CN=Computers,${page.rootDN()}`,
  async onCreated(name, container) {
    notify.success(`Created ${name}`);
    await page.showCreated(`CN=${name},${container}`, name);
  },
});
addButton.addEventListener('click', () => newComputer.open());
page.domainReady.then((rootDN) => {
  addButton.disabled = !rootDN;
  if (!rootDN) addButton.title = 'Unavailable until the directory responds';
});
