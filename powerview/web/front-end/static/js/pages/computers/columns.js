import { attribute, isController, values } from '../../core/directory.js';
import { dnChipColumn } from '../../components/grid/chips.js';
import { countColumn, createColumnSet, dnColumn, nameColumn, statusColumn, textColumn, timeColumn } from '../../components/grid/columns.js';

const ipAddresses = (record) => values(attribute(record, 'IPAddress')).map(String).filter(Boolean);

const ipAddressColumn = {
  key: 'ipAddress', label: 'IPAddress', hint: 'Resolved from AD DNS', icon: 'field-text', width: 200,
  attributes: ['dNSHostName'],
  request: { include_ip: true },
  text: (record) => ipAddresses(record).join(', '),
  filter: { type: 'values', values: ipAddresses },
};

const lapsColumn = (column) => ({ ...column, attributes: [], request: { include_laps: true } });

export const computerColumns = createColumnSet({
  storageKey: 'powerview.computers.columns',
  objectClass: 'computer',
  name: nameColumn((record) => (isController(record) ? 'controller' : 'computer')),
  catalog: [
    textColumn('dnsHostName', 'dNSHostName', 'DNS host name', 240),
    statusColumn,
    textColumn('os', 'operatingSystem', 'Operating system', 240),
    ipAddressColumn,
    lapsColumn(timeColumn('lapsExpiry', 'ms-Mcs-AdmPwdExpirationTime', 'Legacy LAPS expiration')),
    lapsColumn(timeColumn('windowsLapsExpiry', 'msLAPS-PasswordExpirationTime', 'Windows LAPS expiration')),
    lapsColumn(textColumn('lapsPassword', 'ms-Mcs-AdmPwd', 'Legacy LAPS password, when readable', 240)),
    lapsColumn(textColumn('windowsLapsPassword', 'msLAPS-Password', 'Windows LAPS password, when readable', 280)),
    textColumn('osVersion', 'operatingSystemVersion', 'OS version', 160),
    textColumn('description', 'description', 'Description', 280, 'field-desc'),
    textColumn('account', 'sAMAccountName', 'Account', 180),
    textColumn('location', 'location', 'Location', 180),
    dnColumn('managedBy', 'managedBy', 'Managed by'),
    countColumn('groups', 'memberOf', 'Groups'),
    dnChipColumn('groupNames', 'memberOf', 'Group names; hover a chip for its DN'),
    timeColumn('lastLogon', 'lastLogonTimestamp', 'Last logon'),
    timeColumn('pwdLastSet', 'pwdLastSet', 'Password last set'),
    timeColumn('created', 'whenCreated', 'Created'),
    timeColumn('modified', 'whenChanged', 'Modified'),
  ],
  defaults: ['dnsHostName', 'status', 'os', 'description', 'lastLogon', 'created'],
});
