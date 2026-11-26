// API client. The access token lives in memory only. The refresh token lives in an
// HttpOnly cookie that scripts cannot read; the server sets it because we send X-Auth-Mode: cookie.

const state = { access: null, expiresAt: 0, refreshing: null, timer: null, listeners: new Set() };

export class ApiError extends Error {
  constructor(status, code, message, data) {
    super(message);
    this.status = status;
    this.code = code;
    this.data = data || {};
  }
}

export const auth = {
  get token() { return state.access; },
  get expiresAt() { return state.expiresAt; },
  get signedIn() { return Boolean(state.access); },
  onChange(fn) { state.listeners.add(fn); return () => state.listeners.delete(fn); },
};

function setTokens(body) {
  state.access = body.access_token;
  state.expiresAt = Date.now() + body.expires_in * 1000;
  clearTimeout(state.timer);
  // Refresh a minute early so a request never goes out with an expired token.
  const delay = Math.max(5, body.expires_in - 60) * 1000;
  state.timer = setTimeout(() => refresh().catch(() => {}), delay);
  state.listeners.forEach((fn) => fn(true));
}

export function clearTokens() {
  state.access = null;
  state.expiresAt = 0;
  clearTimeout(state.timer);
  state.listeners.forEach((fn) => fn(false));
}

async function parse(res) {
  if (res.status === 204) return null;
  const text = await res.text();
  try { return text ? JSON.parse(text) : null; } catch { return null; }
}

function toError(res, body) {
  const e = body && body.error ? body.error : {};
  const retry = res.headers.get('Retry-After');
  return new ApiError(res.status, e.code || 'error', e.message || res.statusText || 'Request failed', { ...e, retryAfter: retry ? Number(retry) : undefined });
}

async function send(path, { method = 'GET', body, token = true, cookie = false } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token && state.access) headers.Authorization = `Bearer ${state.access}`;
  if (cookie) headers['X-Auth-Mode'] = 'cookie';
  return fetch(path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
}

/**
 * One refresh at a time. Refresh tokens are single-use, so two parallel refreshes would look
 * like token theft to the server and revoke the session. Everyone shares one in-flight promise.
 */
export function refresh() {
  if (!state.refreshing) {
    state.refreshing = (async () => {
      const res = await send('/api/auth/refresh', { method: 'POST', body: {}, token: false, cookie: true });
      const body = await parse(res);
      if (!res.ok) { clearTokens(); throw toError(res, body); }
      setTokens(body);
    })().finally(() => { state.refreshing = null; });
  }
  return state.refreshing;
}

export async function api(path, opts = {}) {
  let res = await send(path, opts);
  if (res.status === 401 && opts.token !== false && state.access) {
    try { await refresh(); res = await send(path, opts); } catch { /* fall through to the 401 */ }
  }
  const body = await parse(res);
  if (!res.ok) {
    if (res.status === 401 && opts.token !== false) clearTokens();
    throw toError(res, body);
  }
  return body;
}

/** Returns {mfaToken} when a second factor is needed, otherwise stores tokens. */
export async function login(email, password) {
  const res = await send('/api/auth/login', { method: 'POST', body: { email, password }, token: false, cookie: true });
  const body = await parse(res);
  if (!res.ok) throw toError(res, body);
  if (body.status === 'mfa_required') return { mfaToken: body.mfa_token };
  setTokens(body);
  return {};
}

export async function loginMfa(mfaToken, code) {
  const res = await send('/api/auth/login/mfa', { method: 'POST', body: { mfa_token: mfaToken, code }, token: false, cookie: true });
  const body = await parse(res);
  if (!res.ok) throw toError(res, body);
  setTokens(body);
}

export async function logout() {
  try { await send('/api/auth/logout', { method: 'POST', cookie: true }); } catch { /* offline: still sign out locally */ }
  clearTokens();
}

export function decodeJwt(token) {
  try {
    const part = (s) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    const [head, payload] = token.split('.');
    return { header: part(head), claims: part(payload) };
  } catch { return null; }
}

/**
 * Teaching aid for the sessions page: send the same refresh token twice at once, like a
 * thief and the real app racing. The server accepts one and treats the other as reuse.
 */
export async function simulateTokenTheft() {
  const call = () => send('/api/auth/refresh', { method: 'POST', body: {}, token: false, cookie: true });
  const results = await Promise.all([call(), call()]);
  clearTokens();
  return results.map((r) => r.status);
}
