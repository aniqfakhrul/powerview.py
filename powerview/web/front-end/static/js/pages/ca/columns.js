import { attribute, values } from '../../core/directory.js';
import { element } from '../../core/dom.js';
import { countColumn, createColumnSet, nameColumn, textColumn } from '../../components/grid/columns.js';

export const isEnabled = (record) => values(attribute(record, 'Enabled'))[0] === true;
export function webEnrollment(record) {
  if (!Object.hasOwn(record.attributes, 'WebEnrollment')) return [];
  const value = record.attributes.WebEnrollment;
  if (value == null) return ['Not checked: the CA has no host name'];
  const endpoints = values(value).filter((item) => typeof item === 'string' && /^https?:\/\//.test(item));
  return endpoints.length ? endpoints : ['No endpoint found: host unreachable or /certsrv missing'];
}

export const findings = (record) => values(attribute(record, 'Vulnerable')).map(String).filter(Boolean);

function booleanColumn(key, name, hint) {
  const flag = (record) => values(attribute(record, name))[0];
  const text = (record) => (flag(record) === true ? 'Yes' : flag(record) === false ? 'No' : '');
  return {
    key, label: name, hint, icon: 'field-class', width: 150, attributes: [name],
    text,
    sort: (record) => (typeof flag(record) === 'boolean' ? Number(flag(record)) : null),
  };
}

const enabledColumn = {
  key: 'enabled', label: 'Enabled', hint: 'Published by at least one certificate authority', icon: 'field-class', width: 110, attributes: ['Enabled'],
  render: (record) => element('span', isEnabled(record) ? 'state' : 'state state--disabled', isEnabled(record) ? 'Enabled' : 'Disabled'),
  text: (record) => (isEnabled(record) ? 'Enabled' : 'Disabled'),
  sort: (record) => Number(!isEnabled(record)),
};

const findingsColumn = {
  key: 'findings', label: 'Vulnerable', hint: 'Template findings reported by PowerView', icon: 'alert', width: 130, attributes: ['Vulnerable'],
  render: (record) => {
    const list = findings(record);
    if (!list.length) return element('span', 'cell-muted', '—');
    const pill = element('span', 'state state--danger', String(list.length));
    pill.title = list.join('\n');
    return pill;
  },
  text: (record) => findings(record).join('; '),
  sort: (record) => findings(record).length,
};

export const templateColumns = createColumnSet({
  storageKey: 'powerview.ca.templates.columns',
  objectClass: null,
  name: nameColumn('certificate'),
  catalog: [
    enabledColumn,
    textColumn('authorities', 'Certificate Authorities', 'Certificate authorities publishing this template', 200),
    textColumn('eku', 'pKIExtendedKeyUsage', 'Extended key usages', 280),
    booleanColumn('clientAuth', 'Client Authentication', 'Usable for client authentication'),
    booleanColumn('managerApproval', 'ManagerApproval', 'Requests need CA manager approval'),
    textColumn('validity', 'pKIExpirationPeriod', 'Validity period', 150),
    countColumn('enrollment', 'Enrollment Rights', 'Principals allowed to enroll'),
    findingsColumn,
    textColumn('displayName', 'displayName', 'Display name'),
    textColumn('owner', 'Owner', 'Template owner'),
    textColumn('extendedRights', 'Extended Rights', 'Principals with extended rights', 240),
    textColumn('writeOwner', 'Write Owner', 'Principals that can change the owner', 240),
    textColumn('writeDacl', 'Write Dacl', 'Principals that can change permissions', 240),
    textColumn('writeProperty', 'Write Property', 'Principals that can edit the template', 240),
    booleanColumn('enrollmentAgent', 'Enrollment Agent', 'Certificate Request Agent usage'),
    booleanColumn('anyPurpose', 'Any Purpose', 'Any Purpose or no usage restriction'),
    textColumn('nameFlag', 'msPKI-Certificate-Name-Flag', 'Subject name flags', 240),
    textColumn('enrollmentFlag', 'msPKI-Enrollment-Flag', 'Enrollment flags', 240),
    textColumn('privateKeyFlag', 'msPKI-Private-Key-Flag', 'Private key flags'),
    textColumn('keySize', 'msPKI-Minimal-Key-Size', 'Minimum key size', 150),
    textColumn('schemaVersion', 'msPKI-Template-Schema-Version', 'Template schema version', 150),
    textColumn('renewal', 'pKIOverlapPeriod', 'Renewal period', 150),
    textColumn('oid', 'msPKI-Cert-Template-OID', 'Template OID', 280),
    textColumn('guid', 'objectGUID', 'Object GUID', 280),
  ],
  defaults: ['enabled', 'authorities', 'eku', 'clientAuth', 'managerApproval', 'validity', 'enrollment', 'findings'],
});

export const authorityColumns = createColumnSet({
  storageKey: 'powerview.ca.authorities.columns',
  objectClass: null,
  name: nameColumn('certificate'),
  catalog: [
    textColumn('host', 'dNSHostName', 'CA server host name', 220),
    textColumn('subject', 'cACertificateDN', 'CA certificate subject', 300),
    countColumn('templates', 'certificateTemplates', 'Published templates'),
    textColumn('displayName', 'displayName', 'Display name'),
    textColumn('guid', 'objectGUID', 'Object GUID', 280),
    {
      key: 'web', label: 'WebEnrollment', hint: 'Web enrollment endpoints; use Check web enrollment', icon: 'field-text', width: 280, attributes: ['WebEnrollment'],
      text: (record) => webEnrollment(record).join('; '),
    },
  ],
  defaults: ['host', 'subject', 'templates'],
});
