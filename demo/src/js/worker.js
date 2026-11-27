// Runs the real authkit service in Python (Pyodide) off the main thread, so Argon2id and
// key generation never block the page.
import { loadPyodide } from '../pyodide/pyodide.mjs';

const ROOT = new URL('../', import.meta.url);
const PYODIDE_PACKAGES = [
  'argon2-cffi', 'cryptography', 'sqlalchemy', 'pydantic', 'fastapi', 'starlette', 'anyio',
];
// Pure-Python wheels that Pyodide does not ship (pinned to the versions in uv.lock).
const PURE_WHEELS = [
  'pyjwt-2.15.1-py3-none-any.whl',
  'segno-1.6.6-py3-none-any.whl',
  'pydantic_settings-2.16.3-py3-none-any.whl',
  'python_dotenv-1.2.4-py3-none-any.whl',
];

let py = null;
let hostModule = null;

const post = (message) => self.postMessage(message);
const bytes = async (path) => new Uint8Array(await (await fetch(new URL(path, ROOT))).arrayBuffer());

async function start() {
  post({ type: 'progress', stage: 'runtime' });
  py = await loadPyodide({
    indexURL: new URL('pyodide/', ROOT).href,
    lockFileURL: new URL('pyodide/pyodide-lock.json', ROOT).href,
  });
  post({ type: 'progress', stage: 'packages' });
  await py.loadPackage(PYODIDE_PACKAGES, { messageCallback() {}, errorCallback() {} });
  for (const wheel of PURE_WHEELS) py.unpackArchive(await bytes(`pyodide/${wheel}`), 'wheel');
  py.unpackArchive(await bytes('py/authkit.zip'), 'zip', { extractDir: '/lib' });
  py.runPython("import sys\nsys.path.insert(0, '/lib')");
  hostModule = py.pyimport('demo_host');
  post({ type: 'progress', stage: 'service' });
  const info = JSON.parse(hostModule.boot());
  post({ type: 'ready', info, python: py.runPython('import sys; sys.version.split()[0]') });
}

const ops = {
  async handle(method, path, query, headers, body) {
    return hostModule.handle(method, path, query, JSON.stringify(headers), body || '');
  },
  async reset() { return hostModule.boot(); },
  async advance(seconds) { return hostModule.advance_clock(seconds); },
  async totp(secret) { return hostModule.totp_code(secret); },
  async snapshot() { return hostModule.snapshot(); },
};

self.onmessage = async ({ data }) => {
  const { id, op, args } = data;
  try {
    post({ type: 'result', id, ok: true, value: await ops[op](...args) });
  } catch (err) {
    post({ type: 'result', id, ok: false, error: String(err && err.message ? err.message : err) });
  }
};

start().catch((err) => post({ type: 'failed', error: String(err && err.message ? err.message : err) }));
