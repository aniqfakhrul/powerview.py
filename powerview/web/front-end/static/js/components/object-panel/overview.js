import { isDN } from '../../core/dn.js';
import { attribute, objectType, recordName, textValue, values } from '../../core/directory.js';
import { accountDisabled, formatTime, toTime } from '../../core/ldap-values.js';
import { button, dnText, element } from '../../core/dom.js';

const GROUP_SCOPES = [[0x2, 'Global'], [0x4, 'Domain local'], [0x8, 'Universal']];
const GROUP_SECURITY = 0x80000000;

const text = (record, name) => textValue(attribute(record, name));

function time(record, name) {
  const value = attribute(record, name);
  const parsed = toTime(value);
  return parsed == null ? '' : formatTime(parsed);
}

function count(record, name) {
  const items = values(attribute(record, name));
  return items.length ? String(items.length) : '';
}

function groupKind(record) {
  const raw = values(attribute(record, 'groupType'))[0];
  const numeric = Number(raw);
  if (!Number.isInteger(numeric)) return textValue(raw);
  const scope = GROUP_SCOPES.find(([flag]) => (numeric & flag) !== 0)?.[1] ?? 'Unknown scope';
  return `${scope} ${(numeric >>> 0) & GROUP_SECURITY ? 'security' : 'distribution'} group`;
}

function operatingSystem(record) {
  return [text(record, 'operatingSystem'), text(record, 'operatingSystemVersion')].filter(Boolean).join(' · ');
}

const FIELDS = {
  user: [
    ['Account', (r) => text(r, 'sAMAccountName')],
    ['User principal name', (r) => text(r, 'userPrincipalName')],
    ['Display name', (r) => text(r, 'displayName')],
    ['Email', (r) => text(r, 'mail')],
    ['Title', (r) => text(r, 'title')],
    ['Department', (r) => text(r, 'department')],
    ['Manager', (r) => text(r, 'manager')],
    ['Last logon', (r) => time(r, 'lastLogonTimestamp')],
    ['Password last set', (r) => time(r, 'pwdLastSet')],
    ['Groups', (r) => count(r, 'memberOf')],
  ],
  group: [
    ['Account', (r) => text(r, 'sAMAccountName')],
    ['Group type', groupKind],
    ['Email', (r) => text(r, 'mail')],
    ['Members', (r) => count(r, 'member')],
    ['Member of', (r) => count(r, 'memberOf')],
    ['Managed by', (r) => text(r, 'managedBy')],
  ],
  computer: [
    ['Account', (r) => text(r, 'sAMAccountName')],
    ['DNS host name', (r) => text(r, 'dNSHostName')],
    ['Operating system', operatingSystem],
    ['Last logon', (r) => time(r, 'lastLogonTimestamp')],
    ['Groups', (r) => count(r, 'memberOf')],
  ],
};

const COMMON = [
  ['Description', (r) => text(r, 'description')],
  ['Created', (r) => time(r, 'whenCreated')],
  ['Modified', (r) => time(r, 'whenChanged')],
];

function statusPill(record) {
  const control = attribute(record, 'userAccountControl');
  if (!values(control).length) return null;
  const disabled = accountDisabled(control);
  return element('span', disabled ? 'state state--disabled' : 'state', disabled ? 'Disabled' : 'Enabled');
}

export function renderOverview(container, record, { onNavigate, status }) {
  const type = objectType(record);
  const summary = element('section', 'overview__summary');
  summary.setAttribute('aria-label', `${recordName(record)} summary`);
  const pill = statusPill(record);
  const dn = element('div', 'overview__dn');
  const copy = button('', { iconName: 'copy', className: 'icon-button', ariaLabel: 'Copy distinguished name' });
  copy.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(record.dn); status.success('Distinguished name copied'); }
    catch { status.error('Clipboard unavailable. Select the distinguished name to copy it.'); }
  });
  dn.append(dnText(element('code'), record.dn), copy);
  if (pill) summary.append(pill);
  summary.append(dn);

  const list = element('dl', 'overview__fields');
  for (const [label, read] of [...(FIELDS[type] ?? []), ...COMMON]) {
    const value = read(record);
    if (!value) continue;
    const term = element('dt', '', label);
    const detail = element('dd');
    if (isDN(value)) {
      const link = dnText(element('button', 'value value--dn'), value);
      link.type = 'button';
      link.addEventListener('click', () => onNavigate(value));
      detail.append(link);
    } else detail.textContent = value;
    list.append(term, detail);
  }
  container.replaceChildren(summary, list);
}
