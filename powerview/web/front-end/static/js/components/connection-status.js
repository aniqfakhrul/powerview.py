const REFRESH_INTERVAL = 60000;
const MIN_CHECK_GAP = 5000;
export const REQUEST_FAILED_EVENT = 'powerview:request-failed';

function describe(info) {
  if (!info) return { state: 'unreachable', identity: 'PowerView unreachable', announce: 'PowerView web server is unreachable' };
  const identity = [info.username, info.domain].filter(Boolean).join('@');
  if (info.status !== 'OK') return { state: 'down', identity: identity ? `${identity} · disconnected` : 'Disconnected', announce: 'Directory connection lost' };
  return { state: 'ok', identity, announce: 'Directory connection restored' };
}

function tooltip(info, state, checkedAt) {
  const time = checkedAt.toLocaleTimeString();
  if (!info) return `PowerView web server did not respond\nLast checked ${time}`;
  return [
    `${state === 'ok' ? 'Connected' : 'Disconnected'}${info.protocol ? ` over ${info.protocol}` : ''}`,
    info.username && `User: ${info.username}`,
    info.domain && `Domain: ${info.domain}`,
    info.ldap_address && `LDAP server: ${info.ldap_address}`,
    info.nameserver && `Name server: ${info.nameserver}`,
    `Last checked ${time}`,
  ].filter(Boolean).join('\n');
}

export function startConnectionStatus(host) {
  const endpoint = new URL('connectioninfo', new URL(host.dataset.apiRoot, window.location.origin));
  const parts = {
    protocol: host.querySelector('.connection__protocol'),
    identity: host.querySelector('.connection__identity'),
    address: host.querySelector('.connection__address'),
    announcer: host.querySelector('.connection__announcer'),
  };
  let pending = null;
  let lastCheck = 0;
  let timer;

  function render(info) {
    const { state, identity, announce } = describe(info);
    const previous = host.dataset.state;
    host.dataset.state = state;
    parts.protocol.textContent = info?.protocol ?? '';
    parts.identity.textContent = identity;
    parts.address.textContent = info?.ldap_address ?? '';
    host.title = tooltip(info, state, new Date());
    if (previous !== 'checking' && previous !== state) parts.announcer.textContent = announce;
  }

  function schedule() {
    clearTimeout(timer);
    if (document.visibilityState === 'visible') timer = setTimeout(check, REFRESH_INTERVAL);
  }

  function check() {
    if (pending) return pending;
    lastCheck = Date.now();
    pending = (async () => {
      try {
        const response = await fetch(endpoint, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error(`Connection check failed (${response.status})`);
        render(await response.json());
      } catch {
        render(null);
      } finally {
        pending = null;
        schedule();
      }
    })();
    return pending;
  }

  function checkSoon() {
    if (Date.now() - lastCheck >= MIN_CHECK_GAP) check();
  }

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') checkSoon();
    else clearTimeout(timer);
  });
  window.addEventListener('focus', checkSoon);
  window.addEventListener(REQUEST_FAILED_EVENT, checkSoon);
  check();
}
