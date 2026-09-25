import { button, element } from '../../core/dom.js';

const EMPTY = '';
const LIST_LIMIT = 300;
const DAY = 86_400_000;
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

const DATE_CONDITIONS = [
  ['', 'Any date'], ['last7', 'Last 7 days'], ['last30', 'Last 30 days'], ['last90', 'Last 90 days'],
  ['older90', 'Older than 90 days'], ['between', 'Between…'], ['notEmpty', 'Has a value'], ['empty', 'Empty'],
];
const NUMBER_CONDITIONS = [['', 'Any value'], ['between', 'Between…'], ['notEmpty', 'Has a value'], ['empty', 'Empty']];

export function filterSpec(column) {
  if (column.filter?.type === 'date' || column.filter?.type === 'number') return column.filter;
  const values = column.filter?.values ?? ((record, entry) => {
    const text = column.text(record, entry);
    return text ? [text] : [];
  });
  return { type: 'values', values, choices: column.filter?.choices ?? [], label: column.filter?.label ?? ((token) => token) };
}

function tokens(spec, entry) {
  const list = spec.values(entry.record, entry);
  return list.length ? [...new Set(list)] : [EMPTY];
}

function inRange(state, value, now = Date.now()) {
  if (state.op === 'empty') return value == null;
  if (value == null) return false;
  switch (state.op) {
    case 'notEmpty': return true;
    case 'last7': return value >= now - 7 * DAY;
    case 'last30': return value >= now - 30 * DAY;
    case 'last90': return value >= now - 90 * DAY;
    case 'older90': return value < now - 90 * DAY;
    case 'between': return (state.from == null || value >= state.from) && (state.to == null || value <= state.to);
    default: return true;
  }
}

export function matchesFilter(spec, state, entry) {
  if (!state) return true;
  if (state.type === 'values') {
    const checked = (token) => (state.mode === 'include' ? state.set.has(token) : !state.set.has(token));
    return tokens(spec, entry).some(checked);
  }
  return inRange(state, spec.value(entry.record, entry));
}

export function isActive(state) {
  if (!state) return false;
  if (state.type === 'values') return state.mode === 'include' || state.set.size > 0;
  return Boolean(state.op) && !(state.op === 'between' && state.from == null && state.to == null);
}

const dayStart = (text) => (text ? new Date(`${text}T00:00:00`).getTime() : null);
const dayEnd = (text) => (text ? new Date(`${text}T23:59:59.999`).getTime() : null);
const dayText = (value) => {
  if (value == null) return '';
  const date = new Date(value);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
};

export function createColumnFilter({ menu, onChange }) {
  let current = null;
  let lastClosed = { trigger: null, at: 0 };
  const dismissing = new WeakSet();

  function place(trigger) {
    const rect = trigger.getBoundingClientRect();
    const width = Math.min(280, window.innerWidth - 16);
    const below = window.innerHeight - rect.bottom - 12;
    const above = rect.top - 12;
    const upward = below < 240 && above > below;
    menu.style.width = `${width}px`;
    menu.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - width - 8))}px`;
    menu.style.top = upward ? 'auto' : `${rect.bottom + 4}px`;
    menu.style.bottom = upward ? `${window.innerHeight - rect.top + 4}px` : 'auto';
    menu.style.maxHeight = `${Math.max(140, upward ? above : below)}px`;
  }

  function footer() {
    const bar = element('div', 'fields-menu__footer');
    const clear = button('Clear filter', { className: 'link-button' });
    clear.addEventListener('click', () => { onChange(current.column.key, null); menu.hidePopover(); });
    const done = button('Done', { className: 'button button--primary' });
    done.addEventListener('click', () => menu.hidePopover());
    bar.append(clear, done);
    return bar;
  }

  function renderValues({ column, spec, entries, state }) {
    const counts = new Map();
    for (const entry of entries) for (const token of tokens(spec, entry)) counts.set(token, (counts.get(token) ?? 0) + 1);
    if (state?.type === 'values') for (const token of state.set) if (!counts.has(token)) counts.set(token, 0);
    for (const choice of spec.choices) if (!counts.has(choice)) counts.set(choice, 0);
    const rank = (token) => (spec.choices.includes(token) ? spec.choices.indexOf(token) : token === EMPTY ? Infinity : spec.choices.length);
    const label = (token) => (token === EMPTY ? '(Empty)' : spec.label(token));
    const all = [...counts.keys()].sort((a, b) => rank(a) - rank(b) || collator.compare(label(a), label(b)));
    let draft = state?.type === 'values' ? { type: 'values', mode: state.mode, set: new Set(state.set) } : { type: 'values', mode: 'exclude', set: new Set() };
    const checked = (token) => (draft.mode === 'include' ? draft.set.has(token) : !draft.set.has(token));
    const setChecked = (token, on) => {
      if ((draft.mode === 'include') === on) draft.set.add(token); else draft.set.delete(token);
    };
    const commit = () => {
      if (draft.mode === 'exclude' && !draft.set.size) onChange(column.key, null);
      else onChange(column.key, { type: 'values', mode: draft.mode, set: new Set(draft.set) });
    };

    const search = element('input', 'text-input');
    Object.assign(search, { type: 'search', placeholder: 'Find a value' });
    search.setAttribute('aria-label', `Find a ${column.label} value`);
    search.hidden = spec.choices.length > 0 || all.length <= 8;
    const selectAll = element('label', 'fields-menu__option column-filter__all');
    const allBox = element('input');
    allBox.type = 'checkbox';
    selectAll.append(allBox, element('span', 'fields-menu__label', 'Select all'));
    const list = element('div', 'fields-menu__list');
    list.setAttribute('role', 'group');
    list.setAttribute('aria-label', `${column.label} values`);
    const note = element('p', 'fields-menu__note');

    const matching = () => {
      const text = search.value.trim().toLocaleLowerCase();
      return text ? all.filter((token) => label(token).toLocaleLowerCase().includes(text)) : all;
    };
    const paintAll = (shown) => {
      const on = shown.filter(checked).length;
      allBox.checked = shown.length > 0 && on === shown.length;
      allBox.indeterminate = on > 0 && on < shown.length;
    };
    const paint = () => {
      const shown = matching();
      list.replaceChildren(...shown.slice(0, LIST_LIMIT).map((token) => {
        const row = element('label', 'fields-menu__option');
        const box = element('input');
        box.type = 'checkbox';
        box.checked = checked(token);
        box.addEventListener('change', () => { setChecked(token, box.checked); paintAll(matching()); commit(); });
        row.append(box, element('span', token === EMPTY ? 'fields-menu__label cell-muted' : 'fields-menu__label', label(token)), element('span', 'fields-menu__hint', String(counts.get(token))));
        return row;
      }));
      note.hidden = shown.length <= LIST_LIMIT;
      note.textContent = `Showing ${LIST_LIMIT} of ${shown.length} values. Refine the search to see more.`;
      if (!shown.length) list.append(element('p', 'fields-menu__note', 'No matching values'));
      paintAll(shown);
    };

    allBox.addEventListener('change', () => {
      const shown = matching();
      if (shown.length === all.length) draft = allBox.checked ? { type: 'values', mode: 'exclude', set: new Set() } : { type: 'values', mode: 'include', set: new Set() };
      else for (const token of shown) setChecked(token, allBox.checked);
      paint();
      commit();
    });
    search.addEventListener('input', paint);
    menu.replaceChildren(search, selectAll, list, note, footer());
    paint();
    (search.hidden ? allBox : search).focus();
  }

  function renderRange({ column, spec, state }) {
    const isDate = spec.type === 'date';
    const draft = state && state.type === spec.type ? { ...state } : { type: spec.type, op: '' };
    const condition = element('select', 'text-input');
    condition.setAttribute('aria-label', `${column.label} condition`);
    for (const [value, label] of isDate ? DATE_CONDITIONS : NUMBER_CONDITIONS) condition.append(new Option(label, value));
    condition.value = draft.op;
    const range = element('div', 'column-filter__range');
    const from = element('input', 'text-input');
    const to = element('input', 'text-input');
    Object.assign(from, { type: isDate ? 'date' : 'number', value: isDate ? dayText(draft.from) : (draft.from ?? '') });
    Object.assign(to, { type: isDate ? 'date' : 'number', value: isDate ? dayText(draft.to) : (draft.to ?? '') });
    from.setAttribute('aria-label', isDate ? 'From date' : 'Minimum');
    to.setAttribute('aria-label', isDate ? 'To date' : 'Maximum');
    if (!isDate) { from.placeholder = 'Min'; to.placeholder = 'Max'; }
    range.append(from, element('span', 'cell-muted', '–'), to);

    const read = (input, end) => {
      if (input.value === '') return null;
      if (isDate) return end ? dayEnd(input.value) : dayStart(input.value);
      const value = Number(input.value);
      return Number.isFinite(value) ? value : null;
    };
    const commit = () => {
      draft.op = condition.value;
      draft.from = draft.op === 'between' ? read(from, false) : null;
      draft.to = draft.op === 'between' ? read(to, true) : null;
      range.hidden = draft.op !== 'between';
      onChange(column.key, isActive(draft) ? { ...draft } : null);
    };
    condition.addEventListener('change', () => { commit(); if (condition.value === 'between') from.focus(); });
    from.addEventListener('input', commit);
    to.addEventListener('input', commit);
    range.hidden = draft.op !== 'between';
    menu.replaceChildren(condition, range, footer());
    condition.focus();
  }

  menu.addEventListener('beforetoggle', (event) => {
    if (event.newState === 'open' || !current) return;
    const { trigger } = current;
    current = null;
    lastClosed = { trigger, at: performance.now() };
    trigger.setAttribute('aria-expanded', 'false');
    requestAnimationFrame(() => {
      const lost = document.activeElement === document.body || menu.contains(document.activeElement);
      if (!current && trigger.isConnected && lost) trigger.focus();
    });
  });

  return {
    open(trigger, context) {
      if (dismissing.has(trigger)) {
        dismissing.delete(trigger);
        if (current?.trigger === trigger) menu.hidePopover();
        return;
      }
      if (menu.matches(':popover-open')) {
        const same = current?.trigger === trigger;
        menu.hidePopover();
        if (same) return;
      }
      current = { trigger, column: context.column };
      menu.setAttribute('aria-label', `Filter ${context.column.label}`);
      trigger.setAttribute('aria-expanded', 'true');
      place(trigger);
      menu.showPopover();
      const spec = filterSpec(context.column);
      if (spec.type === 'values') renderValues({ ...context, spec });
      else renderRange({ ...context, spec });
    },
    pressed(trigger, event) {
      const justClosed = lastClosed.trigger === trigger && lastClosed.at >= event.timeStamp;
      if (current?.trigger === trigger || justClosed) dismissing.add(trigger); else dismissing.delete(trigger);
    },
    openKey: () => (menu.matches(':popover-open') ? current?.column.key : null),
    close() { if (menu.matches(':popover-open')) menu.hidePopover(); },
    isOpenFor: (key) => current?.column.key === key && menu.matches(':popover-open'),
  };
}
