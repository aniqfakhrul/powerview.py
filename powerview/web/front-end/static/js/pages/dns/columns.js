import { textValue, values } from '../../core/directory.js';
import { createColumnSet, nameColumn } from '../../components/grid/columns.js';

// Parsed DNS fields are case-sensitive: Name is an SRV target, name is the node.
function field(key, label, hint, width = 180, numeric = false) {
  const value = (record) => record.attributes[label];
  return {
    key, label, hint, width, icon: 'field-text', attributes: [label],
    text: (record) => textValue(value(record)),
    ...(numeric ? { sort: (record) => {
      const raw = values(value(record))[0];
      return raw == null || raw === '' || !Number.isFinite(Number(raw)) ? null : Number(raw);
    } } : {}),
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
  name: nameColumn('domain'),
  catalog: [
    field('type', 'RecordType', 'Record type', 110),
    field('address', 'Address', 'Address or alias', 240),
    field('target', 'Name', 'SRV target', 240),
    field('port', 'Port', 'SRV port', 90, true),
    field('ttl', 'TTL', 'Time to live (seconds)', 110, true),
    {
      ...field('timestamp', 'TimeStamp', 'Dynamic record aging time; Static records have none', 190, true),
      text: (record) => agingText(values(record.attributes.TimeStamp)[0]),
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
