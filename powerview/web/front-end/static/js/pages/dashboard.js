import { createActionMenu } from '../components/action-menu.js';
import { beginLoading } from '../components/loading.js';
import { createStatus } from '../components/status.js';
import { createTabIndicator } from '../components/tab-indicator.js';
import { createAPI } from '../core/api.js';
import { element } from '../core/dom.js';
import { bar, createLinks, remember } from './dashboard/dom.js';
import { ago, clock, listed, moment } from './dashboard/format.js';
import { createDashboardInspector } from './dashboard/inspector.js';
import { createPrivilegedView } from './dashboard/privileged.js';
import { createReviewQueue } from './dashboard/review.js';
import { renderInfrastructure, renderInventory, renderPolicy } from './dashboard/sections.js';
import { signals, sources, thresholdSources } from './dashboard/signals.js';

const root = document.querySelector('#dashboard');
const find = (id) => document.getElementById(id);
const request = createAPI(new URL(root.dataset.apiRoot, location.origin));
const status = createStatus();
const refresh = find('dashboard-refresh');
const live = find('dashboard-live');
const exportButton = find('dashboard-export');
const daysSelect = find('dashboard-days');
const assessmentTabs = [...find('assessment-tabs').querySelectorAll('[role="tab"]')];
const syncAssessmentIndicator = createTabIndicator(find('assessment-tabs'));
const DAYS_KEY = 'powerview.dashboard.inactiveDays';
const DOMAIN_CHANGED = 'The connected domain changed during collection. Refresh to collect a consistent snapshot.';

const view = {
  data: {},
  failures: {},
  queue: new Set(),
  requested: 0,
  refreshing: false,
  collecting: false,
  delayed: false,
  days: 90,
  links: createLinks(root),
  waiting(source) { return this.queue.has(source); },
  placeholder(build) { return this.delayed ? build() : []; },
  fill(text) { return text.replaceAll('{days}', String(this.days)); },
  retry(source) { collect({ sources: [source], fresh: true }); },
  afterRender() { markInspected(); },
};

try {
  const saved = localStorage.getItem(DAYS_KEY);
  if ([...daysSelect.options].some((option) => option.value === saved)) view.days = Number(saved);
} catch { /* per-viewer convenience only */ }
daysSelect.value = String(view.days);

const review = createReviewQueue(view);
const privileged = createPrivilegedView(view);
let inspected = '';
let announced = '';
let reported = '';
let queued = null;

createDashboardInspector({
  root,
  status,
  getRootDN: () => Object.values(view.data)[0]?.root_dn,
  onSaved: () => collect({ fresh: true }),
  onInspect(dn) {
    inspected = dn;
    markInspected();
  },
});
createActionMenu({ trigger: find('dashboard-more'), menu: find('dashboard-menu') });

function selectAssessment(tab) {
  for (const item of assessmentTabs) {
    const selected = item === tab;
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
    find(item.getAttribute('aria-controls')).hidden = !selected;
  }
  syncAssessmentIndicator(true);
  remember('view', tab.id === 'privileged-tab' ? 'privileged' : '');
}

for (const [index, tab] of assessmentTabs.entries()) {
  tab.addEventListener('click', () => selectAssessment(tab));
  tab.addEventListener('keydown', (event) => {
    const next = { ArrowRight: (index + 1) % assessmentTabs.length, ArrowLeft: (index + assessmentTabs.length - 1) % assessmentTabs.length, Home: 0, End: assessmentTabs.length - 1 }[event.key];
    if (next === undefined) return;
    event.preventDefault();
    assessmentTabs[next].focus();
    selectAssessment(assessmentTabs[next]);
  });
}

function markInspected() {
  for (const link of root.querySelectorAll('.dashboard__scroll [data-inspect-dn]')) {
    const current = Boolean(inspected) && link.dataset.inspectDn === inspected;
    if (current) link.setAttribute('aria-current', 'true'); else link.removeAttribute('aria-current');
    link.closest('tr')?.classList.toggle('is-inspected', current);
  }
}

function collectionErrors() {
  const messages = Object.entries(view.failures).map(([source, message]) => [sources[source], message]);
  if (view.data.inventory?.ca_error) messages.push(['Certificate authorities', view.data.inventory.ca_error]);
  return messages;
}

function renderErrors(issues) {
  const grouped = new Map();
  for (const [label, message] of issues) grouped.set(message, [...(grouped.get(message) ?? []), label]);
  const lines = [...grouped].map(([message, labels]) => `${listed(labels)} unavailable: ${message}`);
  if (lines.join('\n') === reported) return;
  reported = lines.join('\n');
  const errors = find('dashboard-errors');
  errors.replaceChildren(...lines.map((line) => element('p', '', line)));
  errors.hidden = !lines.length;
}

function renderIdentity() {
  const current = Object.values(view.data)[0];
  find('dashboard-domain').textContent = current ? current.domain || current.root_dn : 'Directory assessment';
  const context = find('dashboard-context');
  if (current) context.textContent = `${current.root_dn}${current.dc ? ` · ${current.dc}` : ''}`;
  else context.replaceChildren(...(view.collecting ? view.placeholder(() => [bar('240px')]) : []));
  const link = find('dashboard-domain-link');
  link.hidden = !current;
  if (current) {
    link.href = view.links.object({ dn: current.root_dn, name: current.domain }).href;
    link.dataset.inspectDn = current.root_dn;
  }
}

function renderFreshness() {
  const results = Object.values(view.data);
  const time = find('dashboard-time');
  const read = results.map((result) => result.read_at ?? result.collected_at).sort((left, right) => Date.parse(left) - Date.parse(right))[0];
  const cached = results.some((result) => result.cached);
  live.hidden = !cached;
  live.disabled = view.collecting;
  if (!read) {
    time.replaceChildren();
    time.removeAttribute('datetime');
    time.removeAttribute('title');
    return;
  }
  time.dateTime = read;
  time.title = `Directory read ${moment(read)}`;
  if (cached) time.textContent = `Cached · read ${ago(read)}`;
  else time.replaceChildren(...clock(read).map((part) => element('span', '', part)));
}

function renderCollection() {
  const issues = collectionErrors();
  renderErrors(issues);
  const loaded = Object.keys(view.data).length;
  const summary = view.collecting
    ? `${view.refreshing ? 'Refreshing' : 'Loading'} · ${view.requested - view.queue.size} of ${view.requested} sources`
    : loaded === Object.keys(sources).length && !issues.length ? 'Snapshot complete' : loaded ? 'Partial snapshot' : 'Snapshot unavailable';
  find('dashboard-state').textContent = summary;
  const message = `${summary} · Current domain, forest-wide CAs · Read-only collection`;
  if (message !== announced) status.idle(announced = message);
  exportButton.disabled = view.collecting || !loaded;
  refresh.disabled = view.collecting;
  daysSelect.disabled = view.collecting;
  renderFreshness();
}

function render() {
  root.classList.toggle('is-loading-delayed', view.delayed);
  renderIdentity();
  renderInventory(view);
  review.render();
  renderPolicy(view);
  renderInfrastructure(view);
  privileged.render();
  renderCollection();
  markInspected();
}

function admit(source, result) {
  const domain = result.root_dn.toLowerCase();
  const settled = Object.entries(view.data).filter(([key]) => !view.queue.has(key));
  if (settled.some(([, value]) => value.root_dn.toLowerCase() !== domain)) return false;
  for (const [key, value] of Object.entries(view.data)) if (value.root_dn.toLowerCase() !== domain) delete view.data[key];
  view.data[source] = result;
  return true;
}

async function collect({ sources: requested = Object.keys(sources), fresh = false } = {}) {
  if (view.collecting) {
    queued = { sources: requested, fresh };
    return;
  }
  view.collecting = true;
  view.refreshing = Object.keys(view.data).length > 0;
  view.requested = requested.length;
  view.queue = new Set(requested);
  for (const source of requested) delete view.failures[source];
  const finishLoading = beginLoading(find('evidence-table'), { onDelay: () => { view.delayed = true; render(); } });
  render();
  for (const source of requested) {
    try {
      const result = await request(`dashboard/${source}?days=${view.days}${fresh ? '&fresh=1' : ''}`);
      if (!result?.root_dn || !result.collected_at) throw new Error('The server returned an incomplete dashboard response.');
      if (!admit(source, result)) {
        view.data = {};
        for (const key of Object.keys(sources)) view.failures[key] ??= DOMAIN_CHANGED;
        break;
      }
    } catch (failure) {
      view.failures[source] = failure.message;
      delete view.data[source];
    }
    view.queue.delete(source);
    render();
  }
  finishLoading();
  view.queue.clear();
  view.collecting = false;
  view.delayed = false;
  render();
  if (queued) {
    const next = queued;
    queued = null;
    collect(next);
  }
}

refresh.addEventListener('click', () => collect({ fresh: true }));
live.addEventListener('click', () => collect({ fresh: true }));
daysSelect.addEventListener('change', () => {
  view.days = Number(daysSelect.value);
  try { localStorage.setItem(DAYS_KEY, String(view.days)); } catch { /* per-viewer convenience only */ }
  collect({ sources: thresholdSources });
});
exportButton.addEventListener('click', () => {
  const limit = Object.values(view.data)[0]?.sample_limit ?? 100;
  const snapshot = {
    exported_at: new Date().toISOString(), scope: 'Current domain, except certificate authorities and published templates, which are forest-wide; objects visible to the connected session',
    limitations: `Configuration signals are not proof of exploitability. Counts cover returned objects; evidence lists up to ${limit} objects per signal in the stated order. Signals overlap. Missing attributes may reflect permissions. Each source records when the directory was read and whether the result came from the query cache.`,
    inactive_days: view.days,
    signals: signals.map((signal) => ({ ...signal, label: view.fill(signal.label), description: view.fill(signal.description) })),
    sources: view.data, errors: Object.fromEntries(collectionErrors()),
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
  const link = element('a');
  link.href = url;
  link.download = `powerview-dashboard-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

root.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') event.target.closest('.dashboard__tip')?.classList.add('is-dismissed');
});
root.addEventListener('focusout', (event) => event.target.closest('.dashboard__tip')?.classList.remove('is-dismissed'));
root.addEventListener('mouseout', (event) => {
  const tip = event.target.closest('.dashboard__tip');
  if (tip && !tip.contains(event.relatedTarget)) tip.classList.remove('is-dismissed');
});
setInterval(() => {
  if (!document.hidden && Object.values(view.data).some((result) => result.cached)) renderFreshness();
}, 30000);

if (new URL(location.href).searchParams.get('view') === 'privileged') selectAssessment(find('privileged-tab'));
collect();
