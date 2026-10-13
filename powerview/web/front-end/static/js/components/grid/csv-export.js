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

export function csvFilename(name, domain, date = new Date()) {
  const environment = typeof domain === 'string' ? domain.trim().toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^[.-]+|[.-]+$/g, '') : '';
  const timestamp = date.toISOString().replace(/[:.]/g, '-');
  return `powerview-${environment || 'unknown-domain'}-${name}-${timestamp}.csv`;
}

export function downloadCsv(name, csv, domain) {
  const url = URL.createObjectURL(new Blob([`﻿${csv}\r\n`], { type: 'text/csv;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = csvFilename(name, domain);
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
