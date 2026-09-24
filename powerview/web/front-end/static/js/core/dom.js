const SPRITE = document.querySelector('[data-sprite]')?.dataset.sprite ?? '';

export function element(tag, className = '', text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function icon(name, className = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', `icon ${className}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(svg.namespaceURI, 'use');
  use.setAttribute('href', `${SPRITE}#${name}`);
  svg.append(use);
  return svg;
}

export function button(label, { iconName, className = 'button', ariaLabel } = {}) {
  const node = element('button', className);
  node.type = 'button';
  if (iconName) node.append(icon(iconName));
  if (label) node.append(element('span', '', label));
  if (ariaLabel) node.setAttribute('aria-label', ariaLabel);
  return node;
}

export function setBusy(form, busy) {
  for (const control of form.querySelectorAll('button, input, select, textarea')) control.disabled = busy;
  form.setAttribute('aria-busy', String(busy));
}
