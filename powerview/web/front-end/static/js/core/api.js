/** Same-session JSON transport. Reads can be cancelled; changes are never retried. */
const REQUEST_FAILED_EVENT = 'powerview:request-failed';
const reportFailure = () => globalThis.dispatchEvent?.(new Event(REQUEST_FAILED_EVENT));

export class APIError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'APIError';
    this.status = status;
  }
}

export function createAPI(baseURL) {
  return async function request(path, { body, signal, mutation = false } = {}) {
    let response;
    try {
      response = await fetch(new URL(path, baseURL), {
        method: body === undefined ? 'GET' : 'POST',
        credentials: 'same-origin',
        headers: body === undefined ? { Accept: 'application/json' } : {
          Accept: 'application/json', 'Content-Type': 'application/json',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
      });
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      reportFailure();
      throw new APIError(mutation
        ? 'The connection was lost. Check the directory before trying this change again; it may have completed.'
        : 'Cannot reach PowerView. Check that your web session is running, then retry.');
    }
    let data;
    try {
      data = await response.json();
    } catch {
      throw new APIError(mutation
        ? 'The server returned an unreadable result. Check the directory before repeating the change.'
        : 'The server did not return JSON. Check your session and retry.', response.status);
    }
    if (!response.ok || data?.error) {
      reportFailure();
      throw new APIError(data?.error || `Request failed (${response.status}). Check your session and permissions.`, response.status);
    }
    if (mutation && data !== true) {
      throw new APIError('PowerView did not confirm this change. Check the CLI logs and refresh the directory before trying again.', response.status);
    }
    return data;
  };
}
