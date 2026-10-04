import { skeletonRows } from '../../components/loading.js';
import { element } from '../../core/dom.js';
import { bar, check, choice, choiceGroup, remember, retryButton, settle } from './dom.js';
import { count, dateValue, moment, numbers } from './format.js';
import { columns, groups, orders, signals, sources } from './signals.js';

const find = (id) => document.getElementById(id);

export function createReviewQueue(view) {
  const rail = find('dashboard-signals');
  const filter = find('evidence-filter');
  const scroller = document.querySelector('.dashboard__table-scroll');
  const choices = new Map();
  const requested = new URL(location.href).searchParams.get('signal');
  let active = signals.find((signal) => signal.key === requested) ?? signals[0];
  let chosen = active.key === requested;

  for (const [group, label] of groups) {
    rail.append(element('h3', '', label));
    for (const signal of signals.filter((item) => item.group === group)) {
      const item = choice('dashboard__signal', '');
      item.control.addEventListener('click', () => select(signal));
      choices.set(signal.key, item);
      rail.append(item.control);
    }
  }
  choiceGroup(rail);
  filter.addEventListener('input', () => {
    render({ resetScroll: true });
    view.afterRender();
  });

  const finding = (signal) => view.data[signal.source]?.findings[signal.key];
  const display = (record, key) => (columns[key].date ? dateValue(record[key]) : record[key] ?? '');
  const searchable = (record) => [record.name, record.dn, ...active.columns.map((key) => display(record, key))].join(' ').toLowerCase();

  function select(signal) {
    active = signal;
    chosen = true;
    filter.value = '';
    remember('signal', signal.key);
    render({ resetScroll: true });
    view.afterRender();
  }

  function autoSelect() {
    if (chosen || ['users', 'computers'].some((source) => view.waiting(source)) || !(view.data.users || view.data.computers)) return;
    active = signals.find((signal) => finding(signal)?.count > 0) ?? active;
    chosen = true;
  }

  function header(key) {
    const cell = element('th', '', key === 'evidence' ? active.evidence : columns[key].label);
    cell.scope = 'col';
    return cell;
  }

  function cell(record, key) {
    const node = element('td', columns[key].mono ? 'dashboard__mono' : '', display(record, key));
    if (columns[key].date && record[key] && record[key] !== 'never') node.title = moment(record[key]);
    return node;
  }

  function row(record) {
    const node = element('tr');
    const name = element('td');
    name.append(view.links.object(record, record.name, active.source));
    node.append(name, ...active.columns.map((key) => cell(record, key)));
    return node;
  }

  function renderRail() {
    for (const signal of signals) {
      const result = finding(signal);
      const waiting = view.waiting(signal.source);
      const { control, name, value } = choices.get(signal.key);
      name.textContent = view.fill(signal.label);
      check(control, signal === active);
      control.dataset.matches = String(Boolean(result?.count));
      control.title = result || waiting ? '' : 'Source unavailable';
      value.classList.toggle('is-refreshing', waiting && Boolean(result));
      if (waiting && !result) value.replaceChildren(...view.placeholder(() => [bar('18px')]));
      else value.textContent = result ? numbers.format(result.count) : '—';
    }
  }

  function renderSummary(result, shown, query, waiting) {
    const all = find('evidence-all');
    all.hidden = !result?.count || !result.ldap_filter;
    if (!all.hidden) {
      const url = view.links.page(active.source);
      url.searchParams.set('ldapfilter', result.ldap_filter);
      all.href = url;
      all.textContent = `View all ${numbers.format(result.count)} in ${sources[active.source]}`;
    }
    const order = orders[result?.order] ? `, ${orders[result.order]}` : '';
    find('evidence-count').textContent = result
      ? `${query ? `${numbers.format(shown)} of ` : ''}${count(result.objects.length, 'sampled object')}${order} · ${count(result.count, 'total match', 'total matches')}`
      : waiting ? '' : 'Not evaluated';
    const empty = find('evidence-empty');
    empty.hidden = shown > 0 || (waiting && !result);
    if (!result) empty.replaceChildren(`${sources[active.source]} could not be read; this signal has not been evaluated. `, retryButton(view, active.source));
    else empty.textContent = result.count === 0 ? 'No matches in the returned directory data.' : 'No sampled objects match this filter.';
  }

  function render({ resetScroll = false } = {}) {
    autoSelect();
    renderRail();
    const result = finding(active);
    const waiting = view.waiting(active.source);
    const skeleton = settle(find('review-evidence'), waiting, Boolean(result));
    find('evidence-title').textContent = view.fill(active.label);
    find('evidence-flag').textContent = active.flag;
    find('evidence-description').textContent = view.fill(active.description);
    filter.disabled = !result;
    const keys = ['name', ...active.columns];
    find('evidence-head').replaceChildren(...keys.map(header));
    const query = filter.value.trim().toLowerCase();
    const objects = (result?.objects ?? []).filter((record) => searchable(record).includes(query));
    find('evidence-rows').replaceChildren(...(skeleton ? view.placeholder(() => skeletonRows(keys.map(() => ''), 6)) : objects.map(row)));
    if (resetScroll) scroller.scrollTop = 0;
    renderSummary(result, objects.length, query, waiting);
  }

  return { render };
}
