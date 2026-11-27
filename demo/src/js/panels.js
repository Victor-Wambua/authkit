// The two always-visible panels: the audit table and the request log.
import { h, clear } from './dom.js';

const ALERT_EVENTS = new Set(['token_reuse_detected', 'login_blocked', 'mfa_blocked']);
const WARN_EVENTS = new Set(['login_failure', 'mfa_failure']);

export const timeOf = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });

function describe(detail) {
  return Object.entries(detail || {})
    .filter(([k]) => k !== 'email')
    .map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`)
    .join(' ');
}

export function renderAudit(root, snapshot, knownIds) {
  const rows = snapshot.audit;
  if (!rows.length) {
    clear(root).append(h('p.empty', {}, 'No events yet. Sign in or register and the first row appears here.'));
    return;
  }
  const body = h('tbody', {}, rows.map((r) => h('tr', { class: `${ALERT_EVENTS.has(r.event) ? 'is-alert' : WARN_EVENTS.has(r.event) ? 'is-warn' : ''} ${knownIds && !knownIds.has(r.id) ? 'is-new' : ''}` },
    h('td.num.nowrap', {}, timeOf(r.at)),
    h('td', {}, h('code.event', {}, r.event), describe(r.detail) ? h('div.detail', {}, describe(r.detail)) : null),
    h('td.who', {}, r.who || h('span.muted', {}, 'unknown')))));
  clear(root).append(h('table.data', {},
    h('caption.sr-only', {}, 'Audit events, newest first'),
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Time'), h('th', { scope: 'col' }, 'Event and detail'), h('th', { scope: 'col' }, 'Account'))),
    body));
}

const MASK = /("(?:password|new_password|current_password)"\s*:\s*)"[^"]*"/g;
const clip = (text) => text.replace(/"([A-Za-z0-9_.\-]{44,})"/g, (_, v) => `"${v.slice(0, 28)}…"`);

function pretty(text) {
  if (!text) return '(empty)';
  try { return clip(JSON.stringify(JSON.parse(text), null, 2)).replace(MASK, '$1"••••••••"'); } catch { return clip(text).slice(0, 600); }
}

export function createWireLog(root) {
  const entries = [];
  const open = new Set();
  let seq = 0;
  const draw = () => {
    if (!entries.length) {
      clear(root).append(h('p.empty', {}, 'No requests yet.'));
      return;
    }
    clear(root).append(h('ul.wire', {}, entries.map((e) => h('li', {},
      h('details', { open: open.has(e.id), ontoggle: (ev) => { if (ev.target.open) open.add(e.id); else open.delete(e.id); } },
        h('summary', {},
          h('span.method', {}, e.method), ' ', h('code', {}, e.path), ' ',
          h('span', { class: `status ${e.response.status >= 400 ? 'bad' : 'good'}` }, String(e.response.status)), ' ',
          h('span.muted.num', {}, `${Math.round(e.response.ms)} ms`), ' ',
          h('span.muted', {}, `· ${e.source}`)),
        e.request ? h('div', {}, h('p.label', {}, 'Request body'), h('pre.code', { tabindex: 0 }, pretty(e.request))) : null,
        h('p.label', {}, 'Response body'),
        h('pre.code', { tabindex: 0 }, pretty(e.response.body)))))));
  };
  draw();
  return {
    add(record) { entries.unshift({ ...record, id: ++seq }); entries.length = Math.min(entries.length, 40); draw(); },
    clear() { entries.length = 0; open.clear(); draw(); },
  };
}
