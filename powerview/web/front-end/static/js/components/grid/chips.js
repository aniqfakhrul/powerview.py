import { attribute, values } from '../../core/directory.js';
import { dnLabel } from '../../core/dn.js';
import { element } from '../../core/dom.js';
import { pill, rangedValues, textColumn } from './columns.js';

const MORE = 'cell-chips__more';
const itemsOf = (cell) => [...cell.children].filter((child) => !child.classList.contains(MORE));

function chipCell(nodes, title) {
  if (!nodes.length) return element('span', 'cell-muted', '—');
  const cell = element('span', 'cell-chips');
  cell.title = title;
  cell.append(...nodes);
  return cell;
}

export function chips(value) {
  const items = values(value).map(String).filter(Boolean);
  return chipCell(items.map((item) => pill(item)), items.join(', '));
}

function dnChip(dn) {
  const chip = element('button', 'state state--neutral cell-chips__link', dnLabel(dn));
  chip.type = 'button';
  chip.title = dn;
  chip.dataset.dnLink = dn;
  return chip;
}

export const chipColumn = (key, name, hint, width) => ({ ...textColumn(key, name, hint, width), render: (record) => chips(attribute(record, name)) });

export function dnChipColumn(key, name, hint, width = 260) {
  const dns = (record) => rangedValues(record, name).items.filter((item) => typeof item === 'string' && item);
  const labels = (record) => dns(record).map(dnLabel);
  return {
    key, label: name, hint, icon: 'field-text', width, attributes: [name],
    text: (record) => [...labels(record), ...dns(record)].join('; '),
    sort: (record) => labels(record)[0]?.toLocaleLowerCase() ?? null,
    filter: { type: 'values', values: labels },
    render: (record) => {
      const { partial } = rangedValues(record, name);
      const note = partial ? `\nThe directory returned the first ${dns(record).length} values; more exist.` : '';
      const cell = chipCell(dns(record).map(dnChip), `${labels(record).join(', ')}${note}`);
      if (partial) cell.dataset.partial = '';
      return cell;
    },
  };
}

export function expandChips(cells) {
  for (const cell of cells) {
    for (const item of itemsOf(cell)) item.hidden = false;
    cell.querySelector(`.${MORE}`)?.remove();
  }
}

export function fitChips(cells) {
  const list = [...cells];
  if (!list.length) return;
  expandChips(list);
  const measured = list.map((cell) => {
    const items = itemsOf(cell);
    const more = element('span', `state state--outline ${MORE}`, `+${items.length}`);
    more.setAttribute('aria-hidden', 'true');
    cell.append(more);
    return { cell, items, more };
  });
  const gap = parseFloat(getComputedStyle(list[0]).columnGap) || 0;
  const layouts = measured.map(({ cell, items, more }) => {
    const box = cell.getBoundingClientRect();
    return { width: box.width, reserve: more.getBoundingClientRect().width + gap, ends: items.map((item) => item.getBoundingClientRect().right - box.left) };
  });
  measured.forEach(({ items, more }, index) => {
    const { width, reserve, ends } = layouts[index];
    const shown = ends.at(-1) <= width ? ends.length : ends.filter((end) => end + reserve <= width).length;
    items.forEach((item, position) => { item.hidden = position >= shown; });
    if (shown === items.length) more.remove();
    else more.textContent = `+${items.length - shown}${more.parentElement.dataset.partial === undefined ? '' : '+'}`;
  });
}
