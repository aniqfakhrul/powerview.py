import { attribute, values } from '../../core/directory.js';
import { countColumn, createColumnSet, dnColumn, nameColumn, statusColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

const ipAddresses = (record) => values(attribute(record, 'IPAddress')).map(String).filter(Boolean);

const ipAddressColumn = {
  key: 'ipAddress', label: 'IPAddress', hint: 'Resolved from AD DNS', icon: 'field-text', width: 200,
  attributes: ['dNSHostName'],
  request: { include_ip: true },
  text: (record) => ipAddresses(record).join(', '),
  filter: { type: 'values', values: ipAddresses },
};

export const computerColumns = createColumnSet({
  storageKey: 'powerview.computers.columns',
  objectClass: 'computer',
  name: nameColumn('computer'),
  catalog: [
    textColumn('dnsHostName', 'dNSHostName', 'DNS host name', 240),
    statusColumn,
    textColumn('os', 'operatingSystem', 'Operating system', 240),
    ipAddressColumn,
    textColumn('osVersion', 'operatingSystemVersion', 'OS version', 160),
    textColumn('description', 'description', 'Description', 280, 'field-desc'),
    textColumn('account', 'sAMAccountName', 'Account', 180),
    textColumn('location', 'location', 'Location', 180),
    dnColumn('managedBy', 'managedBy', 'Managed by'),
    countColumn('groups', 'memberOf', 'Groups'),
    timeColumn('lastLogon', 'lastLogonTimestamp', 'Last logon'),
    timeColumn('pwdLastSet', 'pwdLastSet', 'Password last set'),
    timeColumn('created', 'whenCreated', 'Created'),
    timeColumn('modified', 'whenChanged', 'Modified'),
  ],
  defaults: ['dnsHostName', 'status', 'os', 'description', 'lastLogon', 'created'],
});
