import { createGridPage } from '../components/grid/grid-page.js';
import { renderSummary } from '../components/object-panel/summary.js';
import { attribute, createDirectory, textValue, values } from '../core/directory.js';
import { button, element } from '../core/dom.js';
import { authorityColumns, findings, isEnabled, templateColumns, webEnrollment } from './ca/columns.js';

const root = document.querySelector('#ca');
const directory = createDirectory(new URL(root.dataset.apiRoot, window.location.origin));
const params = new URLSearchParams(window.location.search);
const view = params.get('view') === 'authorities' ? 'authorities' : 'templates';

const list = (record, name) => values(attribute(record, name)).map(String).filter(Boolean);
const flag = (record, name) => {
  const value = values(attribute(record, name))[0];
  return typeof value === 'boolean' ? [value ? 'Yes' : 'No'] : [];
};

function templateSummary(panel, entry) {
  if (!entry) { renderSummary(panel, []); return; }
  const { record } = entry;
  renderSummary(panel, [
    { label: 'Enabled', values: [isEnabled(record) ? 'Enabled' : 'Disabled'], tone: isEnabled(record) ? 'success' : 'disabled' },
    { label: 'Certificate Authorities', values: list(record, 'Certificate Authorities') },
    { label: 'Vulnerable', values: findings(record), tone: 'danger' },
    { label: 'pKIExtendedKeyUsage', values: list(record, 'pKIExtendedKeyUsage') },
    { label: 'Client Authentication', values: flag(record, 'Client Authentication') },
    { label: 'Enrollment Agent', values: flag(record, 'Enrollment Agent') },
    { label: 'Any Purpose', values: flag(record, 'Any Purpose') },
    { label: 'ManagerApproval', values: flag(record, 'ManagerApproval') },
    { label: 'pKIExpirationPeriod', values: list(record, 'pKIExpirationPeriod') },
    { label: 'pKIOverlapPeriod', values: list(record, 'pKIOverlapPeriod') },
    { label: 'Owner', values: list(record, 'Owner') },
    { label: 'Enrollment Rights', values: list(record, 'Enrollment Rights') },
    { label: 'Extended Rights', values: list(record, 'Extended Rights') },
    { label: 'Write Owner', values: list(record, 'Write Owner') },
    { label: 'Write Dacl', values: list(record, 'Write Dacl') },
    { label: 'Write Property', values: list(record, 'Write Property') },
    ...(attribute(record, 'Linked Groups') != null ? [{ label: 'Linked Groups', values: list(record, 'Linked Groups') }] : []),
  ]);
}

function templatesView() {
  const authoritySelect = document.querySelector('#ca-authority');
  const stateSelect = document.querySelector('#ca-state');
  let all = null;
  let authority = params.get('authority') ?? '';
  let state = ['enabled', 'findings'].includes(params.get('state')) ? params.get('state') : '';
  stateSelect.value = state;

  function remember() {
    const url = new URL(window.location.href);
    url.searchParams.set('view', 'templates');
    for (const [key, value] of [['authority', authority], ['state', state]]) {
      if (value) url.searchParams.set(key, value); else url.searchParams.delete(key);
    }
    history.replaceState(null, '', url);
  }

  function syncAuthorities() {
    const publishing = all.flatMap((entry) => list(entry.record, 'Certificate Authorities'));
    const selected = authority && authority !== '-' ? [authority] : [];
    const names = [...new Set([...publishing, ...selected])].sort((a, b) => a.localeCompare(b));
    const options = [new Option('All templates', ''), ...names.map((name) => new Option(name, name)), new Option('Not published', '-')];
    authoritySelect.replaceChildren(...options);
    authoritySelect.value = authority;
    authoritySelect.disabled = false;
    remember();
  }

  function matches(entry) {
    const published = list(entry.record, 'Certificate Authorities');
    if (authority === '-' ? published.length : authority && !published.includes(authority)) return false;
    if (state === 'enabled') return isEnabled(entry.record);
    if (state === 'findings') return findings(entry.record).length > 0;
    return true;
  }

  const page = createGridPage({
    root,
    noun: { singular: 'template', plural: 'templates' },
    columnSet: templateColumns,
    search: false,
    deletable: false,
    summary: { label: 'Summary', render: templateSummary },
    async fetch({ signal, fresh }) {
      if (!all || fresh) {
        all = await directory.certificateTemplates({ signal, fresh });
        syncAuthorities();
      }
      return all.filter(matches);
    },
  });

  for (const control of [authoritySelect, stateSelect]) {
    control.addEventListener('change', () => {
      if (!page.closeDetails()) {
        authoritySelect.value = authority;
        stateSelect.value = state;
        return;
      }
      authority = authoritySelect.value;
      state = stateSelect.value;
      remember();
      page.reload();
    });
  }
}

function authoritiesView() {
  const webButton = document.querySelector('#ca-web');
  let checkWeb = false;
  const webResults = new Map();

  const page = createGridPage({
    root,
    noun: { singular: 'authority', plural: 'authorities' },
    columnSet: authorityColumns,
    search: false,
    deletable: false,
    summary: {
      label: 'Templates',
      render(panel, entry) {
        const published = entry ? list(entry.record, 'certificateTemplates').sort((a, b) => a.localeCompare(b)) : [];
        renderSummary(panel, [
          { label: 'dNSHostName', values: entry ? list(entry.record, 'dNSHostName') : [] },
          { label: 'certificateTemplates', values: published },
          ...(entry && webEnrollment(entry.record).length ? [{ label: 'WebEnrollment', values: webEnrollment(entry.record) }] : []),
        ]);
        if (entry) {
          const show = button('Show templates');
          show.addEventListener('click', () => {
            window.location.assign(`?view=templates&authority=${encodeURIComponent(textValue(attribute(entry.record, 'name')))}`);
          });
          const footer = element('p', 'summary-actions');
          footer.append(show);
          panel.append(footer);
        }
      },
    },
    async fetch({ signal, fresh }) {
      const entries = await directory.certificateAuthorities({ signal, fresh: fresh || checkWeb, checkWeb });
      for (const entry of entries) {
        const key = entry.dn.toLowerCase();
        if (checkWeb) webResults.set(key, entry.record.attributes.WebEnrollment ?? null);
        if (webResults.has(key)) entry.record.attributes.WebEnrollment = webResults.get(key);
      }
      return entries;
    },
  });

  webButton.addEventListener('click', async () => {
    checkWeb = true;
    webButton.disabled = true;
    try {
      await page.reload(true);
    } finally {
      checkWeb = false;
      webButton.disabled = false;
    }
  });
}

if (view === 'authorities') authoritiesView(); else templatesView();
