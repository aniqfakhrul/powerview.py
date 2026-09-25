const SECTIONS = [['machineConfig', 'Computer'], ['userConfig', 'User']];

const BOILERPLATE = new Set(['Unicode', 'Version']);

function flatten(value, path, rows) {
  if (value == null || value === '') return;
  if (path.length === 3 && path[1] === 'Security' && BOILERPLATE.has(path[2])) return;
  if (Array.isArray(value)) {
    if (value.every((item) => item === null || typeof item !== 'object')) rows.push({ label: path.join(' › '), values: value.map(String) });
    else value.forEach((item, index) => flatten(item, [...path, String(index + 1)], rows));
    return;
  }
  if (typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) flatten(item, [...path, key], rows);
    return;
  }
  const text = String(value);
  rows.push({ label: path.join(' › '), values: text.includes(',') && !text.includes(' ') ? text.split(',') : [text] });
}

export function settingRows(settings) {
  const rows = [];
  for (const [key, label] of SECTIONS) flatten(settings?.[key], [label], rows);
  return rows;
}
