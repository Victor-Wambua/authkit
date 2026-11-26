import { h, logo } from './dom.js';
import { api, auth, refresh } from './api.js';
import { runCleanups } from './lifecycle.js';
import * as A from './views-auth.js';
import * as V from './views-app.js';

const root = document.getElementById('app');
let renderId = 0;

function parseHash() {
  const raw = location.hash.replace(/^#/, '') || '/signin';
  const [path, qs] = raw.split('?');
  const parts = path.split('/').filter(Boolean);
  return { name: parts[0] || 'signin', sub: parts[1], query: new URLSearchParams(qs || '') };
}

function mount(node) {
  root.replaceChildren(node);
  const heading = root.querySelector('h1');
  if (heading) heading.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

function plainFrame(...children) {
  return h('main#main.content.centered', {},
    h('div.page-head', {}, h('a.brand', { href: '#/signin' }, logo(32), 'Authkit'), h('a.btn.btn-secondary.btn-sm', { href: '#/signin' }, 'Back to sign in')),
    ...children);
}

const PUBLIC_VIEWS = {
  signin: () => A.signInView(),
  register: () => A.registerView(),
  forgot: () => A.forgotView(),
  reset: (r) => A.resetView(r),
  verify: (r) => A.verifyView(r),
  mfa: () => A.mfaView(),
  mailbox: () => plainFrame(V.mailboxView()),
};
const GUEST_ONLY = new Set(['signin', 'register', 'forgot', 'mfa']);

async function render() {
  const id = ++renderId;
  runCleanups();
  const route = parseHash();

  if (route.name === 'app') {
    if (!auth.signedIn) { location.hash = '#/signin'; return; }
    let me;
    try { me = await api('/api/me'); } catch { location.hash = '#/signin'; return; }
    if (id !== renderId) return;
    const page = route.sub || 'overview';
    const pages = {
      overview: () => V.overviewView(me),
      security: () => V.securityView(me, () => render()),
      sessions: () => V.sessionsView(me),
      activity: () => V.activityView(),
      admin: () => (me.role === 'admin' ? V.adminView() : null),
      mailbox: () => (A.env.dev ? V.mailboxView() : null),
    };
    const make = pages[page];
    const content = make ? make() : null;
    if (!content) { location.hash = '#/app/overview'; return; }
    mount(V.appShell(me, page, content));
    return;
  }

  if (auth.signedIn && GUEST_ONLY.has(route.name)) { location.hash = '#/app'; return; }
  const make = PUBLIC_VIEWS[route.name];
  if (!make) { location.hash = '#/signin'; return; }
  mount(make(route));
}

async function boot() {
  try {
    const res = await fetch('/api/dev/outbox', { headers: { Accept: 'application/json' } });
    A.env.dev = res.ok;
  } catch { A.env.dev = false; }
  try { await refresh(); } catch { /* not signed in */ }
  auth.onChange((signedIn) => { if (!signedIn && parseHash().name === 'app') location.hash = '#/signin'; });
  window.addEventListener('hashchange', render);
  render();
}

boot();
