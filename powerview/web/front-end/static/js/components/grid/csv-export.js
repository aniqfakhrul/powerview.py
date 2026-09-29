const FORMULA = /^[=+\-@\t\r\n\uFF1D\uFF0B\uFF0D\uFF20]/;
const NUMBER = /^-?\d+(\.\d+)?$/;

export function csvCell(value) {
  const text = String(value ?? '');
  const safe = FORMULA.test(text) && !NUMBER.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}

export function toCsv(columns, entries) {
  const lines = [columns.map((column) => column.label), ...entries.map((entry) => columns.map((column) => column.value(entry)))];
  return lines.map((cells) => cells.map(csvCell).join(',')).join('\r\n');
}

export function downloadCsv(name, csv) {
  const url = URL.createObjectURL(new Blob([`﻿${csv}\r\n`], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `powerview-${name}-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
