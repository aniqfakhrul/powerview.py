import { countColumn, createColumnSet, nameColumn, statusColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

export const userColumns = createColumnSet({
  storageKey: 'powerview.users.columns',
  objectClass: 'user',
  name: nameColumn('user'),
  catalog: [
    textColumn('account', 'sAMAccountName', 'Account', 180),
    statusColumn,
    textColumn('description', 'description', 'Description', 320, 'field-desc'),
    textColumn('mail', 'mail', 'Email', 240),
    textColumn('displayName', 'displayName', 'Display name', 220),
    textColumn('upn', 'userPrincipalName', 'User principal name', 260),
    textColumn('title', 'title', 'Title'),
    textColumn('department', 'department', 'Department', 180),
    countColumn('groups', 'memberOf', 'Groups'),
    timeColumn('lastLogon', 'lastLogonTimestamp', 'Last logon'),
    timeColumn('pwdLastSet', 'pwdLastSet', 'Password last set'),
    timeColumn('created', 'whenCreated', 'Created'),
    timeColumn('modified', 'whenChanged', 'Modified'),
  ],
  defaults: ['account', 'status', 'description', 'mail', 'lastLogon', 'created'],
});
