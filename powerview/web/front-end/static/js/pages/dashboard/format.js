export const numbers = new Intl.NumberFormat();
const dates = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const times = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' });
const moments = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
const lists = new Intl.ListFormat(undefined, { type: 'conjunction' });

export const count = (value, singular, plural = `${singular}s`) => `${numbers.format(value)} ${value === 1 ? singular : plural}`;
export const listed = (items) => lists.format(items);
export const moment = (value) => moments.format(new Date(value));
export const clock = (value) => [dates.format(new Date(value)), times.format(new Date(value))];
export const period = (days) => (days % 365 ? count(days, 'day') : count(days / 365, 'year'));

export function ago(value, now = Date.now()) {
  const minutes = Math.floor((now - Date.parse(value)) / 60000);
  if (minutes < 1) return 'less than a minute ago';
  return minutes < 60 ? relative.format(-minutes, 'minute') : relative.format(-Math.floor(minutes / 60), 'hour');
}

export function dateValue(value) {
  if (value === 'never') return 'Never';
  return value ? dates.format(new Date(value)) : 'Not reported';
}
