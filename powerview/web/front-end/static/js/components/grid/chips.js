import { values } from '../../core/directory.js';
import { element } from '../../core/dom.js';
import { pill } from './columns.js';

const MORE = 'cell-chips__more';
const itemsOf = (cell) => [...cell.children].filter((child) => !child.classList.contains(MORE));

export function chips(value) {
  const items = values(value).map(String).filter(Boolean);
  if (!items.length) return element('span', 'cell-muted', '—');
  const cell = element('span', 'cell-chips');
  cell.title = items.join(', ');
  cell.append(...items.map((item) => pill(item)));
  return cell;
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
    else more.textContent = `+${items.length - shown}`;
  });
}
