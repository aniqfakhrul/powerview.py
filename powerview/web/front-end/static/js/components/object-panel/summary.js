import { element } from '../../core/dom.js';

export function renderSummary(panel, rows) {
  const table = element('table', 'property-grid');
  const columns = element('colgroup');
  columns.append(element('col', 'property-grid__name'), element('col'));
  const body = element('tbody');
  for (const { label, values, tone } of rows) {
    const row = element('tr');
    const cell = element('td');
    if (!values.length) cell.append(element('span', 'value value--empty', 'None'));
    for (const value of values) {
      const item = element('span', 'value');
      if (tone) item.append(element('span', `state state--${tone}`, String(value)));
      else item.textContent = String(value);
      cell.append(item);
    }
    row.append(element('th', '', label), cell);
    body.append(row);
  }
  table.append(columns, body);
  panel.replaceChildren(table);
}
