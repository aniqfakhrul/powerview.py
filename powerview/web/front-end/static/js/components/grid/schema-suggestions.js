import { element } from '../../core/dom.js';

const LIMIT = 50;

export function matchSchema(schema, query, excluded) {
  if (!schema || !query) return [];
  return schema.filter((item) => {
    const name = item.name.toLowerCase();
    return name.includes(query) && !excluded.has(name);
  });
}

function suggestionRow(attribute, onPick) {
  const row = element('label', 'fields-menu__option');
  const box = element('input');
  box.type = 'checkbox';
  box.disabled = attribute.kind === 'binary';
  box.setAttribute('aria-label', box.disabled ? `${attribute.name}, binary, not displayable` : `${attribute.name}, schema attribute`);
  box.addEventListener('change', () => onPick(attribute));
  row.append(box, element('span', 'fields-menu__label', attribute.name), element('span', 'fields-menu__hint', attribute.kind));
  return row;
}

export function renderSuggestions(host, { matches, objectClass, onPick }) {
  host.replaceChildren();
  if (!matches.length) return;
  host.append(element('p', 'fields-menu__section', `Schema · ${objectClass}`));
  host.append(...matches.slice(0, LIMIT).map((attribute) => suggestionRow(attribute, onPick)));
  if (matches.length > LIMIT) host.append(element('p', 'fields-menu__more', `${matches.length - LIMIT} more; keep typing to narrow the list`));
}
