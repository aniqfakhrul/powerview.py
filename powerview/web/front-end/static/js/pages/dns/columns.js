import { textValue, values } from '../../core/directory.js';
import { createColumnSet, nameColumn, pill } from '../../components/grid/columns.js';

// Parsed DNS fields are case-sensitive: Name is an SRV target, name is the node.
function field(key, label, hint, width = 180, isNumeric = false) {
  const value = (record) => record.attributes[label];
  const numeric = isNumeric && ((record) => {
    const raw = values(value(record))[0];
    return raw == null || raw === '' || !Number.isFinite(Number(raw)) ? null : Number(raw);
  });
  return {
    key, label, hint, width, icon: 'field-text', attributes: [label],
    text: (record) => textValue(value(record)),
    ...(numeric ? { sort: numeric, filter: { type: 'number', value: numeric } } : {}),
  };
}

const FILETIME_HOURS_OFFSET = 11644473600;
const agingFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function agingText(raw) {
  if (raw == null || raw === '') return '';
  const hours = Number(raw);
  if (!Number.isFinite(hours)) return String(raw);
  if (hours === 0) return 'Static';
  return agingFormat.format((hours * 3600 - FILETIME_HOURS_OFFSET) * 1000);
}

export const dnsColumns = createColumnSet({
  storageKey: 'powerview.dns.columns',
  objectClass: null,
  name: nameColumn('globe'),
  catalog: [
    { ...field('type', 'RecordType', 'Record type', 110), render: (record) => pill(textValue(record.attributes.RecordType)) },
    field('address', 'Address', 'Address or alias', 240),
    { ...field('target', 'Name', 'SRV target, returned as Name', 240), label: 'Target' },
    field('port', 'Port', 'SRV port', 90, true),
    field('ttl', 'TTL', 'Time to live (seconds)', 110, true),
    {
      ...field('timestamp', 'TimeStamp', 'Dynamic record aging time; Static records have none', 190, true),
      text: (record) => agingText(values(record.attributes.TimeStamp)[0]),
      filter: { type: 'values', values: (record) => {
        const raw = values(record.attributes.TimeStamp)[0];
        if (raw == null || raw === '') return [];
        return [Number(raw) === 0 ? 'Static' : 'Dynamic'];
      } },
    },
    field('priority', 'Priority', 'SRV priority', 110, true),
    field('weight', 'Weight', 'SRV weight', 110, true),
    field('serial', 'Serial', 'SOA serial', 130, true),
    field('updatedSerial', 'UpdatedAtSerial', 'Record update serial', 160, true),
    field('primary', 'Primary Server', 'SOA primary server', 240),
    field('admin', 'Zone Admin Email', 'SOA administrator', 240),
    field('refresh', 'Refresh', 'SOA refresh interval (seconds)', 130, true),
    field('retry', 'Retry', 'SOA retry interval (seconds)', 130, true),
    field('expire', 'Expire', 'SOA expiration (seconds)', 130, true),
    field('minimum', 'Minimum', 'SOA minimum TTL (seconds)', 130, true),
  ],
  defaults: ['type', 'address', 'target', 'port', 'ttl', 'timestamp'],
});
