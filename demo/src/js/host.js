// Main-thread side of the in-page service: talks to the worker, plays the part of the browser's
// network stack and cookie jar, and keeps a log of every request for the demo panels.

export function createHost() {
  const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  const pending = new Map();
  const listeners = { progress: [], request: [], reset: [] };
  const jar = new Map(); // name -> { value, path }. Not readable by page scripts, like HttpOnly.
  let nextId = 1;
  let readyInfo = null;
  let resolveReady;
  let rejectReady;
  const ready = new Promise((res, rej) => { resolveReady = res; rejectReady = rej; });

  worker.onmessage = ({ data }) => {
    if (data.type === 'progress') listeners.progress.forEach((fn) => fn(data.stage));
    else if (data.type === 'ready') { readyInfo = { ...data.info, python: data.python }; resolveReady(readyInfo); }
    else if (data.type === 'failed') rejectReady(new Error(data.error));
    else if (data.type === 'result') {
      const entry = pending.get(data.id);
      pending.delete(data.id);
      if (data.ok) entry.resolve(data.value); else entry.reject(new Error(data.error));
    }
  };
  worker.onerror = (event) => rejectReady(new Error(event.message || 'The Python worker stopped.'));

  function call(op, ...args) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, op, args });
    });
  }

  function cookieHeader(path) {
    const parts = [];
    for (const [name, c] of jar) if (path.startsWith(c.path)) parts.push(`${name}=${c.value}`);
    return parts.join('; ');
  }

  function storeCookies(headerPairs) {
    for (const [name, value] of headerPairs) {
      if (name.toLowerCase() !== 'set-cookie') continue;
      const [pair, ...attrs] = value.split(';').map((s) => s.trim());
      const eq = pair.indexOf('=');
      const key = pair.slice(0, eq);
      const val = pair.slice(eq + 1);
      const attr = Object.fromEntries(attrs.map((a) => { const i = a.indexOf('='); return i < 0 ? [a.toLowerCase(), ''] : [a.slice(0, i).toLowerCase(), a.slice(i + 1)]; }));
      if (attr['max-age'] === '0' || val === '' || val === '""') jar.delete(key);
      else jar.set(key, { value: val, path: attr.path || '/' });
    }
  }

  /** Low-level request. Resolves with { status, headers, body, ms }. */
  async function send(method, url, { headers = {}, body, source = 'walkthrough' } = {}) {
    await ready;
    const [path, query = ''] = url.split('?');
    const sent = {
      accept: 'application/json',
      'user-agent': navigator.userAgent,
      ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
    };
    const cookie = cookieHeader(path);
    if (cookie) sent.cookie = cookie;
    const started = performance.now();
    const raw = JSON.parse(await call('handle', method, path, query, sent, body ?? ''));
    const ms = performance.now() - started;
    storeCookies(raw.headers);
    const result = { status: raw.status, headers: raw.headers.filter(([k]) => k.toLowerCase() !== 'set-cookie'), body: raw.body, ms, clockOffset: raw.clock_offset };
    const record = { method, path: query ? `${path}?${query}` : path, source, request: body ?? '', response: result, at: Date.now() };
    listeners.request.forEach((fn) => fn(record));
    return result;
  }

  /** A fetch() look-alike, used by the framed web UI. */
  async function frameFetch(input, init = {}, source = 'web app') {
    const url = typeof input === 'string' ? input : input.url;
    const headers = {};
    new Headers(init.headers || (typeof input === 'string' ? undefined : input.headers)).forEach((v, k) => { headers[k] = v; });
    const res = await send((init.method || 'GET').toUpperCase(), url, { headers, body: typeof init.body === 'string' ? init.body : undefined, source });
    const noBody = res.status === 204 || res.status === 304;
    return new Response(noBody ? null : res.body, { status: res.status, headers: res.headers });
  }

  async function reset() {
    jar.clear();
    const info = JSON.parse(await call('reset'));
    readyInfo = { ...readyInfo, ...info };
    listeners.reset.forEach((fn) => fn());
    return readyInfo;
  }

  return {
    ready,
    send,
    fetch: frameFetch,
    reset,
    info: () => readyInfo,
    advance: async (seconds) => JSON.parse(await call('advance', seconds)),
    totp: async (secret) => JSON.parse(await call('totp', secret)),
    snapshot: async () => JSON.parse(await call('snapshot')),
    on: (event, fn) => listeners[event].push(fn),
  };
}
