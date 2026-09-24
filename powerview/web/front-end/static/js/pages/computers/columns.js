import { countColumn, createColumnSet, dnColumn, nameColumn, statusColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

export const computerColumns = createColumnSet({
  storageKey: 'powerview.computers.columns',
  name: nameColumn('computer'),
  catalog: [
    textColumn('dnsHostName', 'DNS host name', 'dNSHostName', 240),
    statusColumn,
    textColumn('os', 'Operating system', 'operatingSystem', 240),
    textColumn('osVersion', 'OS version', 'operatingSystemVersion', 160),
    textColumn('description', 'Description', 'description', 280, 'field-desc'),
    textColumn('account', 'Account', 'sAMAccountName', 180),
    textColumn('location', 'Location', 'location', 180),
    dnColumn('managedBy', 'Managed by', 'managedBy'),
    countColumn('groups', 'Groups', 'memberOf'),
    timeColumn('lastLogon', 'Last logon', 'lastLogonTimestamp'),
    timeColumn('pwdLastSet', 'Password last set', 'pwdLastSet'),
    timeColumn('created', 'Created', 'whenCreated'),
    timeColumn('modified', 'Modified', 'whenChanged'),
  ],
  defaults: ['dnsHostName', 'status', 'os', 'description', 'lastLogon', 'created'],
});
