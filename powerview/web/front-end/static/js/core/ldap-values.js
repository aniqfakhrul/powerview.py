const ACCOUNT_DISABLED = 0x2;
const FILETIME_EPOCH_OFFSET = 11644473600000;
const GENERALIZED_TIME = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?(?:Z|[+-]\d{4})?$/;
const DAY_FIRST = /^(\d{2})\/(\d{2})\/(\d{4})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?/;
const SERVER_TIME = /^\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}(?: \(([^)]+)\))?$/;
const MIN_YEAR = 1602;
const MAX_YEAR = 9998;

const first = (value) => (Array.isArray(value) ? value[0] : value);

export function accountDisabled(value) {
  const items = Array.isArray(value) ? value : [value];
  return items.some((item) => {
    if (typeof item === 'number') return (item & ACCOUNT_DISABLED) !== 0;
    const text = String(item ?? '').trim();
    if (/^\d+$/.test(text)) return (Number(text) & ACCOUNT_DISABLED) !== 0;
    return /\bACCOUNTDISABLE\b/i.test(text);
  });
}

function valid(time) {
  if (!Number.isFinite(time)) return null;
  const year = new Date(time).getUTCFullYear();
  return year >= MIN_YEAR && year <= MAX_YEAR ? time : null;
}

export function toTime(value) {
  const item = first(value);
  if (item == null || item === '') return null;
  const text = String(item).trim();
  let match = text.match(GENERALIZED_TIME);
  if (match) {
    const [, year, month, day, hour, minute, second] = match.map(Number);
    return valid(Date.UTC(year, month - 1, day, hour, minute, second));
  }
  if (typeof item === 'number' || /^\d+$/.test(text)) {
    const ticks = Number(text);
    return ticks > 0 ? valid(ticks / 10000 - FILETIME_EPOCH_OFFSET) : null;
  }
  match = text.match(DAY_FIRST);
  if (match) {
    const [, day, month, year, hour = 0, minute = 0, second = 0] = match.map((part) => Number(part ?? 0));
    return valid(Date.UTC(year, month - 1, day, hour, minute, second));
  }
  return valid(Date.parse(text));
}

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const detailFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
export const formatTime = (time) => (time == null ? '' : dateFormat.format(time));

export function readableTime(text) {
  const match = text.match(SERVER_TIME);
  if (!match && !(GENERALIZED_TIME.test(text) && text.endsWith('Z'))) return null;
  const time = toTime(text);
  return time == null ? null : { text: detailFormat.format(time), relative: match?.[1] ?? '' };
}
