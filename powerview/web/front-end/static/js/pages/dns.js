import { createGridPage } from '../components/grid/grid-page.js';
import { notify } from '../components/notify.js';
import { createDirectory, recordName, textValue } from '../core/directory.js';
import { dnLabel, splitDN } from '../core/dn.js';
import { dnsColumns } from './dns/columns.js';
import { createNewRecord } from './dns/new-record.js';

const root = document.querySelector('#dns');
const directory = createDirectory(new URL(root.dataset.apiRoot, window.location.origin));
const select = document.querySelector('#dns-zone');
const params = new URLSearchParams(window.location.search);
let zone = params.get('zone') ?? zoneOf(params.get('dn')) ?? '';

function zoneOf(dn) {
  const parts = dn ? splitDN(dn) : [];
  const index = parts.findIndex((part) => /^CN=MicrosoftDNS$/i.test(part));
  return index >= 1 ? parts[index - 1].replace(/^DC=/i, '') : null;
}

function rememberZone() {
  const url = new URL(window.location.href);
  if (zone) url.searchParams.set('zone', zone); else url.searchParams.delete('zone');
  history.replaceState(null, '', url);
}
let zonesReady = null;

function domainZone(rootDN) {
  return splitDN(rootDN ?? '').filter((part) => /^DC=/i.test(part)).map((part) => part.slice(3)).join('.').toLowerCase();
}

function loadZones(fresh) {
  if (!zonesReady || fresh) {
    select.disabled = true;
    zonesReady = directory.dnsZones({ fresh }).then(async (records) => {
      const names = [...new Set(records.map(recordName))].sort((a, b) => a.localeCompare(b));
      if (!names.includes(zone)) {
        const domain = domainZone(await page.domainReady);
        zone = names.find((name) => name.toLowerCase() === domain) ?? names[0] ?? '';
      }
      select.replaceChildren(...names.map((name) => new Option(name, name)));
      if (!names.length) select.append(new Option('No DNS zones', ''));
      select.value = zone;
      select.disabled = !names.length;
      rememberZone();
      syncNewButton();
    }).catch((error) => {
      zonesReady = null;
      select.replaceChildren(new Option('Zones unavailable', ''));
      throw error;
    });
  }
  return zonesReady;
}

const isApex = (dn) => dnLabel(dn) === '@';

function describeRecord(item) {
  const type = textValue(item.record.attributes.RecordType);
  const value = textValue(item.record.attributes.Address) || textValue(item.record.attributes.Name);
  return [type, value].filter(Boolean).join(' ');
}

const page = createGridPage({
  root,
  noun: { singular: 'record', plural: 'records' },
  columnSet: dnsColumns,
  search: false,
  isProtected: isApex,
  afterDelete: () => page.reload(true),
  describeRemoval(record, siblings) {
    const listed = siblings.map(describeRecord).filter(Boolean);
    return {
      title: `Delete ${dnLabel(record.dn)}.${zone}?`,
      message: listed.length > 1
        ? `This removes all ${listed.length} records at this name: ${listed.join(', ')}.`
        : `This removes the DNS record${listed.length ? ` ${listed[0]}` : ''} from ${zone}.`,
    };
  },
  async fetch({ signal, fresh }) {
    await loadZones(fresh);
    if (signal.aborted) return [];
    return zone ? directory.dnsRecords(zone, { signal, fresh }) : [];
  },
});

const newButton = document.querySelector('#dns-new');
const newRecord = createNewRecord({
  directory,
  zone: () => zone,
  async onCreated(name, target) {
    notify.success(`Created ${name}.${target}`);
    if (target === zone) await page.reload(true);
  },
});

function syncNewButton() {
  newButton.disabled = !zone;
  newButton.title = zone ? `New A record in ${zone}` : 'Unavailable until a DNS zone loads';
}

newButton.addEventListener('click', () => { if (zone) newRecord.open(); });

select.addEventListener('change', () => {
  if (!page.closeDetails()) { select.value = zone; return; }
  zone = select.value;
  rememberZone();
  syncNewButton();
  page.reload();
});
