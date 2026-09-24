import { createGridPage } from '../components/grid/grid-page.js';
import { notify } from '../components/notify.js';
import { userColumns } from './users/columns.js';
import { createNewUser } from './users/new-user.js';

const page = createGridPage({
  root: document.querySelector('#users'),
  endpoint: 'get/domainuser',
  noun: { singular: 'user', plural: 'users' },
  columnSet: userColumns,
});

const newButton = document.querySelector('#user-new');
const newUser = createNewUser({
  directory: page.directory,
  defaultContainer: () => `CN=Users,${page.rootDN()}`,
  async onCreated(name) {
    notify.success(`Created ${name}`);
    await page.reloadAndFind(name);
  },
});

newButton.addEventListener('click', () => newUser.open());
page.domainReady.then((rootDN) => {
  newButton.disabled = !rootDN;
  if (!rootDN) newButton.title = 'Unavailable until the directory responds';
});
