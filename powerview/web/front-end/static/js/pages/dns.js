import { createGridPage } from '../components/grid/grid-page.js';
import { createDirectory, recordName } from '../core/directory.js';
import { splitDN } from '../core/dn.js';
import { dnsColumns } from './dns/columns.js';

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

function loadZones(fresh) {
  if (!zonesReady || fresh) {
    select.disabled = true;
    zonesReady = directory.dnsZones({ fresh }).then((records) => {
      const names = [...new Set(records.map(recordName))].sort((a, b) => a.localeCompare(b));
      if (!names.includes(zone)) zone = names[0] ?? '';
      select.replaceChildren(...names.map((name) => new Option(name, name)));
      if (!names.length) select.append(new Option('No DNS zones', ''));
      select.value = zone;
      select.disabled = !names.length;
      rememberZone();
    }).catch((error) => {
      zonesReady = null;
      select.replaceChildren(new Option('Zones unavailable', ''));
      throw error;
    });
  }
  return zonesReady;
}

const page = createGridPage({
  root,
  noun: { singular: 'record', plural: 'records' },
  columnSet: dnsColumns,
  search: false,
  deletable: false,
  async fetch({ signal, fresh }) {
    await loadZones(fresh);
    if (signal.aborted) return [];
    return zone ? directory.dnsRecords(zone, { signal, fresh }) : [];
  },
});

select.addEventListener('change', () => {
  if (!page.closeDetails()) { select.value = zone; return; }
  zone = select.value;
  rememberZone();
  page.reload();
});
