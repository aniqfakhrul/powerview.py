import { countColumn, createColumnSet, nameColumn, statusColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

export const userColumns = createColumnSet({
  storageKey: 'powerview.users.columns',
  name: nameColumn('user'),
  catalog: [
    textColumn('account', 'Account', 'sAMAccountName', 180),
    statusColumn,
    textColumn('description', 'Description', 'description', 320, 'field-desc'),
    textColumn('mail', 'Email', 'mail', 240),
    textColumn('displayName', 'Display name', 'displayName', 220),
    textColumn('upn', 'User principal name', 'userPrincipalName', 260),
    textColumn('title', 'Title', 'title'),
    textColumn('department', 'Department', 'department', 180),
    countColumn('groups', 'Groups', 'memberOf'),
    timeColumn('lastLogon', 'Last logon', 'lastLogonTimestamp'),
    timeColumn('pwdLastSet', 'Password last set', 'pwdLastSet'),
    timeColumn('created', 'Created', 'whenCreated'),
    timeColumn('modified', 'Modified', 'whenChanged'),
  ],
  defaults: ['account', 'status', 'description', 'mail', 'lastLogon', 'created'],
});
