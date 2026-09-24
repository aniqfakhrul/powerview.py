/** Split RDNs without treating escaped commas (or quoted values) as separators. */
export function splitDN(dn) {
  const parts = [];
  let start = 0;
  let quoted = false;
  for (let index = 0; index < dn.length; index += 1) {
    if (dn[index] === '\\') { index += 1; continue; }
    if (dn[index] === '"') quoted = !quoted;
    if (dn[index] === ',' && !quoted) {
      parts.push(dn.slice(start, index).trim());
      start = index + 1;
    }
  }
  if (dn.slice(start).trim()) parts.push(dn.slice(start).trim());
  return parts;
}

export const parentDN = (dn) => splitDN(dn).slice(1).join(',');
export const isDN = (text) => /^(?:CN|OU|DC)=[^,]+(?:,(?:CN|OU|DC|O|L)=[^,]+)*$/i.test(text);
export const sameDN = (left, right) => left.toLowerCase() === right.toLowerCase();

export function dnLabel(dn) {
  const rdn = splitDN(dn)[0] || dn;
  const value = rdn.slice(rdn.indexOf('=') + 1);
  return value.replace(/(?:\\[\da-f]{2})+/gi, (sequence) => {
    const bytes = sequence.match(/[\da-f]{2}/gi).map((hex) => parseInt(hex, 16));
    return new TextDecoder().decode(new Uint8Array(bytes));
  }).replace(/\\(.)/g, '$1');
}

export function namingContext(dn, roots) {
  return [...roots].sort((a, b) => b.length - a.length)
    .find((root) => sameDN(dn, root) || dn.toLowerCase().endsWith(`,${root.toLowerCase()}`));
}
