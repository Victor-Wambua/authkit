// Page wiring: starts the service, then connects the header, the walkthrough, the web app
// frame and the audit and request panels.
import { createHost } from './host.js';
import { h, clear } from './dom.js';
import { mountLab } from './lab.js';
import { renderAudit, createWireLog } from './panels.js';

const $ = (id) => document.getElementById(id);
const host = createHost();
window.__authkitDemo = host; // the framed web UI reaches the service through this

const app = {
  host,
  snap: null,
  known: new Set(),
  subs: [],
  async refresh() {
    app.snap = await host.snapshot();
    app.subs.forEach((fn) => fn(app.snap));
    return app.snap;
  },
  async advanceClock(seconds) {
    await host.advance(seconds);
    await app.refresh();
  },
};

// ---- loading ----------------------------------------------------------

const STAGES = ['runtime', 'packages', 'service'];
host.on('progress', (stage) => {
  const at = STAGES.indexOf(stage);
  document.querySelectorAll('#stages li').forEach((li, i) => {
    li.dataset.state = i < at ? 'done' : i === at ? 'active' : 'todo';
    if (i === at) li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current');
  });
});

// ---- header: clock and reset ------------------------------------------

function showClock(snap) {
  const now = new Date(snap.now);
  $('clock-time').textContent = now.toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium', hour12: false });
  $('clock-time').setAttribute('datetime', snap.now);
  const drift = Math.round((now.getTime() - Date.now()) / 60000);
  $('clock-offset').textContent = drift >= 1 ? ` (+${drift >= 1440 ? `${(drift / 1440).toFixed(1)} days` : `${drift} min`} ahead)` : '';
}

// ---- tabs -------------------------------------------------------------

const TABS = [
  { key: 'walkthrough', tab: 'tab-walkthrough', panel: 'panel-walkthrough', title: 'Authkit demo: walkthrough' },
  { key: 'app', tab: 'tab-app', panel: 'panel-app', title: 'Authkit demo: web app' },
];

function selectTab(key, { focus = false } = {}) {
  for (const t of TABS) {
    const on = t.key === key;
    const tab = $(t.tab);
    tab.setAttribute('aria-selected', String(on));
    tab.tabIndex = on ? 0 : -1;
    $(t.panel).hidden = !on;
    if (on) { document.title = t.title; if (focus) tab.focus(); }
  }
  if (key === 'app') {
    const frame = $('app-frame');
    if (!frame.getAttribute('src')) frame.setAttribute('src', './app/index.html');
  }
  history.replaceState(null, '', key === 'app' ? '#web-app' : '#walkthrough');
}

function wireTabs() {
  TABS.forEach((t, i) => {
    $(t.tab).addEventListener('click', () => selectTab(t.key));
    $(t.tab).addEventListener('keydown', (e) => {
      const move = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (e.key === 'Home' || e.key === 'End') { e.preventDefault(); selectTab(TABS[e.key === 'Home' ? 0 : TABS.length - 1].key, { focus: true }); }
      else if (move) { e.preventDefault(); selectTab(TABS[(i + move + TABS.length) % TABS.length].key, { focus: true }); }
    });
  });
  selectTab(location.hash === '#web-app' ? 'app' : 'walkthrough');
}

// ---- start ------------------------------------------------------------

async function start() {
  let info;
  try {
    info = await host.ready;
  } catch (err) {
    $('loading').hidden = true;
    const failed = $('failed');
    failed.hidden = false;
    failed.textContent = `The service could not start in this browser (${err.message}). It needs WebAssembly and module workers, which every current browser has. The code and README are on GitHub.`;
    return;
  }

  $('argon').textContent = `${info.argon2.memory_kib / 1024} MiB, ${info.argon2.time_cost} passes, ${info.argon2.parallelism} lane`;
  $('pyver').textContent = info.python.split('.').slice(0, 2).join('.');
  $('seed-accounts').append(...info.accounts.map((a) => h('tr', {}, h('td', {}, a.role), h('td', {}, h('code', {}, a.email)), h('td', {}, h('code', {}, a.password)))));

  const wire = createWireLog($('wire'));
  host.on('request', (record) => wire.add(record));
  const lab = mountLab($('lab'), app);

  app.subs.push((snap) => {
    renderAudit($('audit'), snap, app.known.size ? app.known : null);
    const fresh = snap.audit.filter((r) => !app.known.has(r.id));
    if (app.known.size && fresh.length) {
      const top = fresh[0];
      $('announce').textContent = `Audit log: ${top.event}${top.who ? ` for ${top.who}` : ''}`;
    }
    snap.audit.forEach((r) => app.known.add(r.id));
    showClock(snap);
    lab.redraw();
  });
  await app.refresh();

  $('loading').hidden = true;
  $('grid').hidden = false;
  wireTabs();
  for (const id of ['adv-15', 'adv-day', 'reset']) $(id).disabled = false;
  $('adv-15').addEventListener('click', () => app.advanceClock(15 * 60));
  $('adv-day').addEventListener('click', () => app.advanceClock(24 * 3600));
  $('reset').addEventListener('click', async () => {
    $('reset').disabled = true;
    await host.reset();
    app.known.clear();
    wire.clear();
    lab.reset();
    const frame = $('app-frame');
    if (frame.getAttribute('src')) frame.contentWindow.location.reload();
    await app.refresh();
    $('announce').textContent = 'Demo reset. Back to the two seeded accounts.';
    $('reset').disabled = false;
  });

  // Keep the page and the framed app on the same theme when the app's toggle is used.
  window.addEventListener('storage', (e) => {
    if (e.key === 'authkit-theme') document.documentElement.dataset.theme = e.newValue || '';
  });

  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    navigator.serviceWorker.register('./sw.js').catch(() => { /* offline support is optional */ });
  }
}

start();
