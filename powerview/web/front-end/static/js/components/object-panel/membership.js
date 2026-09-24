import { dnLabel, parentDN } from '../../core/dn.js';
import { values } from '../../core/directory.js';
import { element, icon } from '../../core/dom.js';

const PAGE_SIZE = 200;
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

function entries(record, name) {
  const lower = name.toLowerCase();
  const keys = Object.keys(record.attributes).filter((key) => key.toLowerCase() === lower || key.toLowerCase().startsWith(`${lower};range=`));
  const dns = keys.flatMap((key) => values(record.attributes[key])).filter((value) => typeof value === 'string');
  const partial = keys.some((key) => key.includes(';'));
  return { dns, partial };
}

export function membershipCount(record, name) {
  return entries(record, name).dns.length;
}

export function renderMembership(container, record, name, { onNavigate, noun }) {
  const { dns, partial } = entries(record, name);
  const items = dns.map((dn) => ({ dn, label: dnLabel(dn), path: parentDN(dn) }))
    .sort((a, b) => collator.compare(a.label, b.label));

  if (!items.length) {
    const empty = element('div', 'panel-message');
    empty.append(element('h2', '', `No ${noun}`), element('p', '', 'The directory returned no values for this object.'));
    container.replaceChildren(empty);
    return;
  }

  const toolbar = element('div', 'membership__toolbar');
  const search = element('label', 'search-field');
  const input = element('input');
  Object.assign(input, { type: 'search', placeholder: `Filter ${noun}` });
  input.setAttribute('aria-label', `Filter ${noun}`);
  search.append(icon('search'), input);
  const count = element('span', 'membership__count');
  toolbar.append(search, count);

  const notes = [];
  if (partial) notes.push(element('p', 'membership__note', 'The directory returned a partial list; large groups may have more members than shown.'));

  const list = element('ul', 'membership__list');
  const more = element('button', 'value-more');
  more.type = 'button';
  let visible = items;
  let shown = 0;

  function row(item) {
    const li = element('li');
    const link = element('button', 'membership__item');
    link.type = 'button';
    link.title = item.dn;
    link.append(icon('object'), element('span', 'membership__name', item.label), element('span', 'membership__path', item.path));
    link.addEventListener('click', () => onNavigate(item.dn));
    li.append(link);
    return li;
  }

  function renderMore() {
    const next = visible.slice(shown, shown + PAGE_SIZE);
    list.append(...next.map(row));
    shown += next.length;
    more.hidden = shown >= visible.length;
    more.textContent = `Show ${Math.min(PAGE_SIZE, visible.length - shown)} more`;
  }

  function update() {
    const query = input.value.trim().toLocaleLowerCase();
    visible = query ? items.filter((item) => item.dn.toLocaleLowerCase().includes(query)) : items;
    count.textContent = query ? `${visible.length} of ${items.length}` : String(items.length);
    list.replaceChildren();
    shown = 0;
    renderMore();
  }

  more.addEventListener('click', renderMore);
  input.addEventListener('input', update);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && input.value) { event.preventDefault(); input.value = ''; update(); }
  });
  container.replaceChildren(toolbar, ...notes, list, more);
  update();
}
