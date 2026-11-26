import { h, icon, logo, toast, guard, clear, relTime, absTime, copyText, downloadText, safeSvg } from './dom.js';
import { api, auth, refresh, logout, decodeJwt, simulateTokenTheft, clearTokens } from './api.js';
import { field, formAlert, describeError, passwordMeter } from './forms.js';
import { describeAgent, describeEvent, EVENT_NAMES } from './ua.js';
import { onCleanup } from './lifecycle.js';
import { env } from './views-auth.js';

/* ---------- shell ---------- */

export function theme() {
  const root = document.documentElement;
  const stored = (() => { try { return localStorage.getItem('authkit-theme'); } catch { return null; } })();
  if (stored) root.dataset.theme = stored;
  const isDark = () => (root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches);
  return {
    isDark,
    toggle() {
      root.dataset.theme = isDark() ? 'light' : 'dark';
      try { localStorage.setItem('authkit-theme', root.dataset.theme); } catch { /* private mode */ }
    },
  };
}
const themeCtl = theme();

export function appShell(me, active, content) {
  const link = (route, ico, label, extra) => h('a', { href: `#/app/${route}`, 'aria-current': active === route ? 'page' : null }, icon(ico), label, extra);
  const themeBtn = h('button.btn.btn-ghost.btn-sm', { type: 'button', 'aria-label': 'Toggle dark mode' }, icon(themeCtl.isDark() ? 'sun' : 'moon'), h('span.theme-label', {}, themeCtl.isDark() ? 'Light mode' : 'Dark mode'));
  themeBtn.addEventListener('click', () => {
    themeCtl.toggle();
    themeBtn.replaceChildren(icon(themeCtl.isDark() ? 'sun' : 'moon'), h('span.theme-label', {}, themeCtl.isDark() ? 'Light mode' : 'Dark mode'));
  });
  const out = h('button.btn.btn-secondary.btn-sm', { type: 'button' }, icon('logout'), 'Sign out');
  out.addEventListener('click', async () => { await logout(); location.hash = '#/signin'; toast('Signed out.'); });
  const initial = me.email.slice(0, 1).toUpperCase();
  return h('div.shell', {},
    h('aside.sidebar', {},
      h('a.brand', { href: '#/app' }, logo(32), 'Authkit'),
      h('nav.nav', { 'aria-label': 'Main' },
        link('overview', 'home', 'Overview'),
        link('security', 'shield', 'Security'),
        link('sessions', 'monitor', 'Devices'),
        link('activity', 'activity', 'Activity'),
        me.role === 'admin' ? link('admin', 'users', 'Admin') : null,
        env.dev ? link('mailbox', 'inbox', 'Dev mailbox') : null),
      h('div.sidebar-foot', {},
        h('div.me', {}, h('div.avatar', { 'aria-hidden': 'true' }, initial), h('div.who', {}, h('b', {}, me.email), h('span', {}, me.role === 'admin' ? 'Administrator' : 'Member'))),
        themeBtn, out)),
    h('main#main.content', {}, content));
}

function pageHead(title, sub, actions) {
  return h('div.page-head', {}, h('div', {}, h('h1', { tabindex: '-1' }, title), sub ? h('p', {}, sub) : null), actions || null);
}

function skeletonRows(n = 3) {
  return h('div', { 'aria-busy': 'true', 'aria-label': 'Loading' }, ...Array.from({ length: n }, () => h('div.skeleton.h-44.my')));
}

function empty(ico, title, text) {
  return h('div.empty', {}, icon(ico), h('b', {}, title), h('span', {}, text));
}

function errorBox(err, retry) {
  return h('div.alert.danger', { role: 'alert' }, icon('alert'), h('div', {}, describeError(err), ' ', retry ? h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: retry }, 'Retry') : null));
}

/** A destructive button that needs a second click within a few seconds. */
function confirmButton(label, confirmLabel, onConfirm, cls = 'btn-danger btn-sm') {
  const classes = cls.split(' ').map((c) => '.' + c).join('');
  const btn = h('button' + '.btn' + classes, { type: 'button' }, label);
  let armed = false;
  let timer;
  btn.addEventListener('click', async () => {
    if (!armed) {
      armed = true;
      btn.textContent = confirmLabel;
      timer = setTimeout(() => { armed = false; btn.textContent = label; }, 4000);
      return;
    }
    clearTimeout(timer);
    armed = false;
    btn.disabled = true;
    try { await onConfirm(); } finally { btn.disabled = false; btn.textContent = label; }
  });
  return btn;
}

/* ---------- overview ---------- */

export function overviewView(me) {
  const stats = h('div.grid-3', {}, ...[1, 2, 3].map(() => h('div.card.stat', {}, h('div.skeleton.h-60'))));
  const tokenCard = h('div.card', {});
  const host = h('div.stack', {},
    pageHead('Overview', `Signed in as ${me.email}`),
    me.email_verified ? null : unverifiedBanner(),
    stats, tokenCard);

  function unverifiedBanner() {
    const btn = h('button.btn.btn-secondary.btn-sm', { type: 'button' }, 'Resend link');
    btn.addEventListener('click', guard(btn, async () => {
      try { await api('/api/auth/email/resend', { method: 'POST' }); toast('Confirmation email sent.'); } catch (e) { toast(describeError(e), 'error'); }
    }));
    return h('div.alert.warn', {}, icon('mail'), h('div.form-row.between', {}, h('span', {}, h('b', {}, 'Confirm your email address. '), 'We sent a link when you registered.'), btn));
  }

  (async () => {
    let sessions = [];
    try { sessions = (await api('/api/me/sessions')).sessions; } catch { /* shown as unknown */ }
    const others = sessions.filter((s) => !s.current).length;
    clear(stats).append(
      h('div.card.stat', {}, h('div.label', {}, 'Two-factor'), h('div.value', {}, me.totp_enabled ? 'On' : 'Off'),
        h('div.sub', {}, me.totp_enabled ? 'Authenticator code required at sign-in.' : h('a', { href: '#/app/security' }, 'Turn it on'))),
      h('div.card.stat', {}, h('div.label', {}, 'Signed-in devices'), h('div.value', {}, String(sessions.length)),
        h('div.sub', {}, others ? h('a', { href: '#/app/sessions' }, `${others} other ${others === 1 ? 'device' : 'devices'}`) : 'Only this one.')),
      h('div.card.stat', {}, h('div.label', {}, 'Email'), h('div.value', {}, me.email_verified ? 'Confirmed' : 'Not confirmed'),
        h('div.sub', {}, `Member since ${new Date(me.created_at).toLocaleDateString(undefined, { dateStyle: 'medium' })}`)));
  })();

  // Live view of the access token: 15-minute lifetime, silent refresh, rotating refresh token.
  const countdown = h('b', {}, '');
  function drawToken() {
    const jwt = auth.token ? decodeJwt(auth.token) : null;
    const claims = jwt ? jwt.claims : {};
    clear(tokenCard).append(
      h('header', {}, h('div', {}, h('h2', {}, 'Your session tokens'),
        h('p', {}, 'The access token lives in memory for 15 minutes and is renewed in the background. The refresh token is an HttpOnly cookie that scripts cannot read, and it changes on every use.')),
        h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: async () => { try { await refresh(); drawToken(); toast('Tokens rotated.'); } catch (e) { toast(describeError(e), 'error'); } } }, icon('refresh'), 'Rotate now')),
      h('dl.token-panel', {},
        h('dt', {}, 'expires in'), h('dd', {}, countdown),
        h('dt', {}, 'alg / kid'), h('dd', {}, jwt ? `${jwt.header.alg} / ${jwt.header.kid}` : 'unknown'),
        h('dt', {}, 'session (sid)'), h('dd', {}, claims.sid || 'unknown'),
        h('dt', {}, 'amr'), h('dd', {}, (claims.amr || []).join(', ') || 'unknown')));
    tick();
  }
  function tick() {
    const left = Math.max(0, Math.round((auth.expiresAt - Date.now()) / 1000));
    countdown.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
  }
  drawToken();
  const unsub = auth.onChange(() => drawToken());
  const timer = setInterval(tick, 1000);
  onCleanup(() => { clearInterval(timer); unsub(); });
  return host;
}

/* ---------- security ---------- */

function reauthForm({ intro, button, tone = 'btn-primary', onDone, run }) {
  const pw = field({ label: 'Current password', type: 'password', autocomplete: 'current-password' });
  const code = field({ label: 'Authentication or recovery code', autocomplete: 'one-time-code', hint: '6-digit code from your app, or a recovery code.', spellcheck: false });
  const alert = formAlert();
  const submit = h('button.btn.' + tone, { type: 'submit' }, button);
  const cancel = h('button.btn.btn-ghost', { type: 'button' }, 'Cancel');
  const form = h('form.form', { novalidate: true }, intro ? h('p.desc', {}, intro) : null, alert.el, pw.root, code.root, h('div.form-row', {}, submit, cancel));
  cancel.addEventListener('click', () => onDone());
  form.addEventListener('submit', guard(submit, async () => {
    alert.hide();
    try { await run({ password: pw.value, code: code.value.trim() }); } catch (err) { alert.show(describeError(err)); }
  }));
  return form;
}

export function securityView(me, rerender) {
  const twofa = h('div.card', {});
  const pwCard = h('div.card', {});
  const dangerCard = h('div.card.danger', {});
  const host = h('div.stack', {}, pageHead('Security', 'Protect your sign-in and control what happens if something goes wrong.'), twofa, pwCard, dangerCard);

  /* two-factor */
  function drawTwoFactor(mode = 'idle', payload) {
    clear(twofa);
    const head = (badge) => h('header', {}, h('div', {}, h('h2', {}, 'Two-factor authentication'),
      h('p', {}, 'Ask for a 6-digit code from an authenticator app (Google Authenticator, 1Password, Authy) after the password.')), badge);

    if (mode === 'codes') {
      const text = payload.join('\n');
      twofa.append(head(h('span.badge.ok', {}, icon('check'), 'On')),
        h('div.alert.warn', {}, icon('alert'), h('div', {}, h('b', {}, 'Save these recovery codes now. '), 'Each works once if you lose your phone. They are shown only this time and stored hashed.')),
        h('ul.recovery', { 'aria-label': 'Recovery codes' }, ...payload.map((c) => h('li', {}, c))),
        h('div.form-row', {},
          h('button.btn.btn-secondary', { type: 'button', onclick: () => copyText(text, 'Recovery codes copied') }, icon('copy'), 'Copy'),
          h('button.btn.btn-secondary', { type: 'button', onclick: () => downloadText('authkit-recovery-codes.txt', `Authkit recovery codes for ${me.email}\n\n${text}\n`) }, icon('download'), 'Download'),
          h('button.btn.btn-primary', { type: 'button', onclick: () => rerender() }, 'I have saved them')));
      return;
    }

    if (mode === 'setup') {
      const code = field({ label: '6-digit code', name: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', maxlength: 6, className: 'code', spellcheck: false });
      const alert = formAlert();
      const verify = h('button.btn.btn-primary', { type: 'submit' }, 'Turn on two-factor');
      const form = h('form.form', { novalidate: true }, alert.el, code.root, h('div.form-row', {}, verify, h('button.btn.btn-ghost', { type: 'button', onclick: () => drawTwoFactor() }, 'Cancel')));
      form.addEventListener('submit', guard(verify, async () => {
        alert.hide();
        try {
          const out = await api('/api/mfa/enable', { method: 'POST', body: { code: code.value.trim() } });
          me.totp_enabled = true;
          drawTwoFactor('codes', out.recovery_codes);
        } catch (err) { alert.show(describeError(err)); code.value = ''; code.input.focus(); }
      }));
      const qr = h('div.qr-frame', {}, h('div.skeleton.qr-skel'));
      const secretLine = h('div.secret', {});
      twofa.append(head(h('span.badge', {}, 'Setting up')),
        h('div.setup-grid', {}, qr,
          h('div.stack.tight', {},
            h('ol.steps', {}, h('li', {}, h('b', {}, 'Scan'), ' the QR code with your authenticator app.'), h('li', {}, h('b', {}, 'Or type'), ' the secret in by hand.'), h('li', {}, h('b', {}, 'Enter'), ' the 6-digit code it shows.')),
            secretLine, form)));
      (async () => {
        try {
          const s = await api('/api/mfa/setup', { method: 'POST' });
          const svg = safeSvg(s.qr_svg);
          qr.replaceChildren(svg || h('span', {}, 'QR unavailable. Use the secret.'));
          secretLine.append(h('span.muted', {}, 'Secret:'), h('code', {}, s.secret), h('button.btn.btn-ghost.btn-sm', { type: 'button', onclick: () => copyText(s.secret, 'Secret copied') }, icon('copy'), 'Copy'));
          code.input.focus();
        } catch (err) { qr.replaceChildren(); twofa.append(errorBox(err)); }
      })();
      return;
    }

    if (!me.totp_enabled) {
      twofa.append(head(h('span.badge.warn', {}, 'Off')),
        h('p.desc', {}, 'Recommended. A stolen password alone will no longer be enough to sign in.'),
        h('div', {}, h('button.btn.btn-primary', { type: 'button', onclick: () => drawTwoFactor('setup') }, icon('shield'), 'Set up two-factor')));
      return;
    }

    const slot = h('div', {});
    const act = (label, which) => h('button.btn.btn-secondary.btn-sm', { type: 'button', onclick: () => drawAction(which) }, label);
    function drawAction(which) {
      if (!which) { clear(slot); return; }
      const regen = which === 'regen';
      slot.replaceChildren(reauthForm({
        intro: regen ? 'This replaces all ten recovery codes. The old ones stop working.' : 'Turning this off makes your account depend on the password alone.',
        button: regen ? 'Replace recovery codes' : 'Turn off two-factor', tone: regen ? 'btn-primary' : 'btn-danger',
        onDone: () => drawAction(null),
        run: async ({ password, code }) => {
          if (regen) {
            const out = await api('/api/mfa/recovery-codes', { method: 'POST', body: { password, code } });
            drawTwoFactor('codes', out.recovery_codes);
          } else {
            await api('/api/mfa/disable', { method: 'POST', body: { password, code } });
            me.totp_enabled = false; toast('Two-factor turned off.'); drawTwoFactor();
          }
        },
      }));
    }
    twofa.append(head(h('span.badge.ok', {}, icon('check'), 'On')),
      h('div.form-row', {}, act('Replace recovery codes', 'regen'), act('Turn off', 'off')), slot);
  }

  /* password */
  function drawPassword() {
    const cur = field({ label: 'Current password', type: 'password', autocomplete: 'current-password' });
    const next = field({ label: 'New password', type: 'password', autocomplete: 'new-password' });
    const meter = passwordMeter(() => next.value);
    next.input.addEventListener('input', meter.update);
    const alert = formAlert();
    const submit = h('button.btn.btn-primary', { type: 'submit' }, 'Change password');
    const form = h('form.form.narrow', { novalidate: true }, alert.el, cur.root, next.root, meter.root, h('div', {}, submit));
    form.addEventListener('submit', guard(submit, async () => {
      alert.hide(); next.setError('');
      try {
        const out = await api('/api/me/password', { method: 'POST', body: { current_password: cur.value, new_password: next.value } });
        cur.value = ''; next.value = ''; meter.update();
        alert.show(out.revoked ? `Password changed. ${out.revoked} other ${out.revoked === 1 ? 'device was' : 'devices were'} signed out.` : 'Password changed.', 'ok');
      } catch (err) {
        if (err.code === 'password_rejected') next.setError(describeError(err)); else alert.show(describeError(err));
      }
    }));
    clear(pwCard).append(h('header', {}, h('div', {}, h('h2', {}, 'Password'), h('p', {}, 'Changing it signs out every other device. Hashed with Argon2id; upgraded automatically when we raise the settings.'))), form);
  }

  /* delete */
  function drawDanger(open = false) {
    clear(dangerCard).append(h('header', {}, h('div', {}, h('h2', {}, 'Delete account'), h('p', {}, 'Removes your account, sessions and recovery codes. The audit log keeps a record that it happened.'))));
    if (!open) {
      dangerCard.append(h('div', {}, h('button.btn.btn-danger', { type: 'button', onclick: () => drawDanger(true) }, icon('trash'), 'Delete my account')));
      return;
    }
    const pw = field({ label: 'Password', type: 'password', autocomplete: 'current-password' });
    const code = me.totp_enabled ? field({ label: 'Authentication code', autocomplete: 'one-time-code', spellcheck: false }) : null;
    const alert = formAlert();
    const submit = h('button.btn.btn-danger', { type: 'submit' }, 'Permanently delete');
    const form = h('form.form.narrow', { novalidate: true }, alert.el, pw.root, code ? code.root : null,
      h('div.form-row', {}, submit, h('button.btn.btn-ghost', { type: 'button', onclick: () => drawDanger(false) }, 'Cancel')));
    form.addEventListener('submit', guard(submit, async () => {
      alert.hide();
      try {
        await api('/api/me', { method: 'DELETE', body: { password: pw.value, code: code ? code.value.trim() : undefined } });
        clearTokens(); location.hash = '#/signin'; toast('Your account was deleted.');
      } catch (err) { alert.show(describeError(err)); }
    }));
    dangerCard.append(form);
  }

  drawTwoFactor(); drawPassword(); drawDanger();
  return host;
}

/* ---------- devices ---------- */

export function sessionsView(me) {
  const list = h('div.card', {}, skeletonRows());
  const actions = h('div', {});
  const drill = h('div.card.flat', {});
  const host = h('div.stack', {}, pageHead('Devices', 'Everywhere your account is signed in. Revoking a device takes effect immediately.', actions), list, drill);

  async function load() {
    try {
      const { sessions } = await api('/api/me/sessions');
      const others = sessions.filter((s) => !s.current);
      clear(actions).append(h('button.btn.btn-secondary', { type: 'button', disabled: others.length === 0, onclick: async () => {
        try { const out = await api('/api/me/sessions/revoke-others', { method: 'POST' }); toast(`Signed out ${out.revoked} other ${out.revoked === 1 ? 'device' : 'devices'}.`); load(); } catch (e) { toast(describeError(e), 'error'); }
      } }, icon('logout'), 'Sign out other devices'));
      if (!sessions.length) { clear(list).append(empty('monitor', 'No active sessions', 'Sign in again to continue.')); return; }
      clear(list).append(h('ul.rows', {}, ...sessions.map((s) => {
        const d = describeAgent(s.user_agent);
        return h('li', {},
          h('div.ico', {}, icon(d.kind)),
          h('div.main', {},
            h('div.title', {}, d.name, s.current ? h('span.badge.ok', {}, 'This device') : null, s.used_2fa ? h('span.badge', {}, icon('shield'), '2FA') : null),
            h('div.meta', {}, `${s.ip || 'Unknown IP'} · signed in ${relTime(s.created_at)} · active ${relTime(s.last_used_at)}`),
            h('div.meta', { title: absTime(s.expires_at) }, `Session ends ${relTime(s.expires_at)} at the latest`)),
          h('div.actions', {}, s.current ? null : confirmButton('Sign out', 'Click to confirm', async () => {
            try { await api(`/api/me/sessions/${s.id}`, { method: 'DELETE' }); toast('Device signed out.'); load(); } catch (e) { toast(describeError(e), 'error'); }
          })));
      })));
    } catch (err) { clear(list).append(errorBox(err, load)); }
  }
  load();

  const result = h('div', { 'aria-live': 'polite' });
  drill.append(h('header', {}, h('div', {}, h('h2', {}, 'Token theft drill'),
    h('p', {}, 'Refresh tokens work once. This sends the same one twice at the same moment, like a thief and the real app racing. The server accepts one, sees the other as a replay, and revokes the whole session. You will be signed out, and the event appears in your activity.'))),
    h('div', {}, h('button.btn.btn-secondary', { type: 'button', onclick: async (e) => {
      e.currentTarget.disabled = true;
      const codes = await simulateTokenTheft();
      location.hash = '#/signin';
      toast(codes.includes(401) ? 'Reuse detected: the session was revoked.' : 'Both calls succeeded; try again.', codes.includes(401) ? 'info' : 'error');
    } }, icon('flame'), 'Run the drill')), result);
  return host;
}

/* ---------- activity & admin ---------- */

function eventRow(item, users) {
  const d = describeEvent(item.event);
  const who = users && item.user_id ? (users.get(item.user_id) || item.user_id.slice(0, 8)) : null;
  const detail = item.detail && item.detail.email ? `attempted as ${item.detail.email}` : null;
  const agent = item.user_agent ? describeAgent(item.user_agent).name : null;
  return h('li', {},
    h('div.ico' + (d.tone ? '.' + d.tone : ''), {}, icon(d.icon)),
    h('div.main', {}, h('div.title', {}, d.label), h('div.meta', {}, [who, item.ip, agent, detail].filter(Boolean).join(' · ') || 'No further details')),
    h('time.meta', { datetime: item.at, title: absTime(item.at) }, relTime(item.at)));
}

function pagedEvents(url, { users, filter } = {}) {
  const list = h('ul.rows', {});
  const more = h('div.form-row.center.mt');
  const card = h('div.card', {}, skeletonRows(4));
  let next = null;
  let first = true;
  async function load(reset = false) {
    if (reset) { next = null; first = true; clear(list); }
    const params = new URLSearchParams({ limit: '25' });
    if (next) params.set('before', String(next));
    if (filter && filter()) params.set('event', filter());
    try {
      const page = await api(`${url}?${params}`);
      if (first) {
        first = false;
        clear(card).append(list, more);
        if (!page.items.length) { clear(card).append(empty('list', 'Nothing here yet', 'Events show up as they happen.')); return; }
      }
      page.items.forEach((i) => list.append(eventRow(i, users)));
      next = page.next_before;
      clear(more);
      if (next) more.append(h('button.btn.btn-secondary', { type: 'button', onclick: () => load() }, 'Load more'));
    } catch (err) { clear(card).append(errorBox(err, () => load(true))); }
  }
  load();
  return { card, reload: () => load(true) };
}

export function activityView() {
  const feed = pagedEvents('/api/me/activity');
  return h('div.stack', {}, pageHead('Activity', 'Recent security events on your account, newest first.'), feed.card);
}

export function adminView() {
  const body = h('div', {});
  let tab = 'audit';
  const tabs = h('div.tabs.narrow-tabs', { role: 'tablist', 'aria-label': 'Admin sections' });
  const users = new Map();

  function drawTabs() {
    clear(tabs).append(...[['audit', 'Audit log'], ['accounts', 'Accounts']].map(([id, label]) =>
      h('button.tab', { type: 'button', role: 'tab', 'aria-selected': String(tab === id), 'aria-current': tab === id ? 'page' : null, onclick: () => { tab = id; drawTabs(); drawBody(); } }, label)));
  }
  async function drawBody() {
    clear(body).append(h('div.card', {}, skeletonRows(4)));
    if (tab === 'accounts') {
      try {
        const { users: list } = await api('/api/admin/users');
        clear(body).append(h('div.card', {}, h('ul.rows', {}, ...list.map((u) => h('li', {},
          h('div.ico', {}, icon(u.role === 'admin' ? 'shield' : 'user')),
          h('div.main', {}, h('div.title', {}, u.email, u.role === 'admin' ? h('span.badge.warn', {}, 'admin') : null), h('div.meta', {}, `Joined ${absTime(u.created_at)}`)),
          h('div.actions', {}, u.email_verified ? h('span.badge.ok', {}, 'Email confirmed') : h('span.badge', {}, 'Unconfirmed'), ' ', u.totp_enabled ? h('span.badge.ok', {}, '2FA') : h('span.badge', {}, 'No 2FA')))))));
      } catch (err) { clear(body).append(errorBox(err, drawBody)); }
      return;
    }
    try {
      const { users: list } = await api('/api/admin/users');
      list.forEach((u) => users.set(u.id, u.email));
    } catch { /* ids are shown instead */ }
    let feed;
    const select = h('select.select', { id: 'evt', 'aria-label': 'Filter by event' }, h('option', { value: '' }, 'All events'), ...EVENT_NAMES.map((n) => h('option', { value: n }, describeEvent(n).label)));
    select.addEventListener('change', () => feed.reload());
    feed = pagedEvents('/api/admin/audit', { users, filter: () => select.value });
    clear(body).append(h('div.stack.tight', {}, h('div.toolbar', {}, h('div.field', {}, h('label', { for: 'evt' }, 'Event'), select)), feed.card));
  }
  drawTabs(); drawBody();
  return h('div.stack', {}, pageHead('Admin', 'Audit log and accounts. Only administrators can see this page; the API enforces it too.'), tabs, body);
}

/* ---------- dev mailbox ---------- */

function linkify(text) {
  const parts = [];
  let last = 0;
  for (const m of text.matchAll(/https?:\/\/[^\s]+/g)) {
    parts.push(text.slice(last, m.index));
    let href = m[0];
    try { const u = new URL(m[0]); if (u.hash) href = u.hash; } catch { /* leave as text */ }
    parts.push(href.startsWith('#') ? h('a', { href }, m[0]) : m[0]);
    last = m.index + m[0].length;
  }
  parts.push(text.slice(last));
  return parts;
}

export function mailboxView() {
  const list = h('div.stack', {}, skeletonRows(2));
  async function load() {
    try {
      const { messages } = await api('/api/dev/outbox', { token: false });
      clear(list);
      if (!messages.length) { list.append(h('div.card', {}, empty('inbox', 'No mail yet', 'Register or request a password reset and the message appears here.'))); return; }
      messages.forEach((m) => list.append(h('div.card.mail', {}, h('header', {}, h('div', {}, h('h3', {}, m.subject), h('p', {}, `To ${m.to} · ${relTime(m.sent_at)}`))), h('pre', {}, ...linkify(m.text)))));
    } catch (err) { clear(list).append(errorBox(err, load)); }
  }
  load();
  const timer = setInterval(load, 4000);
  onCleanup(() => clearInterval(timer));
  return h('div.stack', {},
    pageHead('Dev mailbox', 'Emails the file mailer wrote to disk. This page exists only when AUTHKIT_ENV=dev; production needs a real SMTP mailer.'),
    list);
}
