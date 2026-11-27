// The guided walkthrough. Every button sends a real request to the in-page service and shows
// what came back. Tokens are handled the way an API client would: in the JSON body.
import { h, clear, decodeJwt, sha256Hex } from './dom.js';
import { timeOf } from './panels.js';

const REASONS = {
  too_short: 'it is shorter than 12 characters',
  too_long: 'it is longer than 128 characters',
  contains_email: 'it contains your email address',
  repetitive_or_sequential: 'it is a repeated or sequential pattern',
  breached: 'it appears in the list of breached passwords',
};

const DEFAULTS = () => ({
  email: 'visitor@example.test',
  password: 'harbour lamp seven quiet orchid',
  access: null,
  chain: [], // refresh tokens in the order they were issued: { raw, hash }
  mfaToken: null,
  secret: null,
  lastUsedCode: null,
  recovery: null,
});

export function mountLab(root, app) {
  let S = DEFAULTS();
  const { host } = app;
  const targets = []; // functions that redraw from S and the latest snapshot
  let authTimer = null;

  // ---- plumbing -------------------------------------------------------

  async function call(method, path, body, { auth = false } = {}) {
    const headers = {};
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (auth && S.access) headers.authorization = `Bearer ${S.access}`;
    const res = await host.send(method, path, { headers, body: body === undefined ? undefined : JSON.stringify(body) });
    let json = null;
    try { json = res.body ? JSON.parse(res.body) : null; } catch { /* not JSON */ }
    const retry = res.headers.find(([k]) => k.toLowerCase() === 'retry-after');
    return { status: res.status, json, ms: Math.round(res.ms), retryAfter: retry ? Number(retry[1]) : json?.error?.retry_after };
  }

  const mono = (text) => h('code', {}, text);
  const ms = (r) => `${r.ms} ms`;

  function say(box, kind, ...parts) {
    clear(box);
    box.className = `result ${kind}`;
    box.append(h('p', {}, ...parts));
  }

  function sayAudit(box, events) {
    if (!events.length) return;
    box.append(h('p.audit-line', {}, 'Audit log gained: ', events.map((e, i) => [i ? ', ' : '', mono(e)])));
  }

  /** Run an action, then refresh the panels and report which audit events it caused. */
  async function act(button, box, fn) {
    const before = app.snap?.audit[0]?.id ?? 0;
    const label = button.textContent;
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try {
      await fn();
    } catch (err) {
      say(box, 'bad', `Something unexpected happened: ${err.message}`);
    } finally {
      button.removeAttribute('aria-busy');
      button.disabled = false;
      button.textContent = label;
    }
    await app.refresh();
    const gained = app.snap.audit.filter((r) => r.id > before).map((r) => r.event).reverse();
    sayAudit(box, gained);
    redraw();
    return gained;
  }

  function sessionState() {
    if (!S.chain.length || !app.snap) return null;
    const hashes = new Set(S.chain.map((t) => t.hash));
    return app.snap.sessions.find((s) => s.tokens.some((t) => hashes.has(t.hash))) || null;
  }
  const sessionLive = () => Boolean(S.access) && sessionState() && !sessionState().revoked_at;

  function storeTokens(json) {
    S.access = json.access_token;
    return sha256Hex(json.refresh_token).then((hash) => { S.chain.push({ raw: json.refresh_token, hash }); });
  }

  const redraw = () => targets.forEach((fn) => fn());

  // ---- building blocks ------------------------------------------------

  function step(n, title, intro, ...body) {
    const id = `step-${n}`;
    return h('li.step', { 'aria-labelledby': id },
      h('div.num', { 'aria-hidden': 'true' }, String(n)),
      h('div.step-body', {},
        h('h3', { id }, title),
        h('p.intro-line', {}, intro),
        ...body));
  }

  function field(label, input, hint) {
    const id = `f-${Math.random().toString(36).slice(2, 8)}`;
    input.id = id;
    return h('div.field', {}, h('label', { for: id }, label), input, hint ? h('p.hint', {}, hint) : null);
  }

  const button = (text, onclick, cls = '') => h('button', { type: 'button', class: `btn ${cls}`.trim(), onclick }, text);
  const resultBox = () => h('div.result', { role: 'status', 'aria-live': 'polite' });

  function chainTable() {
    const holder = h('div.chain');
    targets.push(() => {
      clear(holder);
      if (!S.chain.length) {
        holder.append(h('p.empty', {}, 'No refresh tokens yet. Sign in in step 1.'));
        return;
      }
      const session = sessionState();
      const dbTokens = new Map((session?.tokens || []).map((t) => [t.hash, t.state]));
      const rows = S.chain.map((t, i) => {
        let state = dbTokens.get(t.hash) || 'unknown';
        let text = { live: 'current, not yet used', used: 'used', expired: 'expired', unknown: 'unknown' }[state];
        if (session?.revoked_at) { state = 'revoked'; text = `revoked (${session.revoked_reason})`; }
        return h('tr', { class: `tok-${state}` },
          h('td.num', {}, String(i + 1)),
          h('td', {}, mono(`${t.raw.slice(0, 16)}…`)),
          h('td', {}, h('span', { class: 'state' }, text)));
      });
      holder.append(
        h('div.scroll-x', { tabindex: 0, role: 'region', 'aria-label': 'Refresh token family table' },
          h('table.data', {},
            h('caption', {}, 'Refresh token family, state read from the ', mono('refresh_tokens'), ' table'),
            h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, '#'), h('th', { scope: 'col' }, 'Token'), h('th', { scope: 'col' }, 'State in the database'))),
            h('tbody', {}, rows))),
        session ? h('p.session-line', {}, 'Session (the token family): ', mono(session.id.slice(0, 8)), ' ',
          session.revoked_at ? h('strong.danger', {}, `revoked at ${timeOf(session.revoked_at)}, reason ${session.revoked_reason}`) : 'active') : null);
    });
    return holder;
  }

  // ---- step 1: register and sign in ----------------------------------

  const s1 = resultBox();
  const emailIn = h('input', { type: 'email', value: S.email, autocomplete: 'off', spellcheck: 'false', inputmode: 'email' });
  const passIn = h('input', { type: 'text', value: S.password, autocomplete: 'off', spellcheck: 'false' });
  const tokensCard = h('div.tokens');

  function describeLoginError(r) {
    if (r.status === 429) return `Too many attempts. The service says to wait ${r.retryAfter} s (HTTP 429).`;
    if (r.status === 401) return 'Email or password is incorrect (HTTP 401). The answer is the same for an unknown address and a wrong password.';
    return `${r.json?.error?.message || 'Request failed'} (HTTP ${r.status}).`;
  }

  const registerBtn = button('Create account', async () => {
    S.email = emailIn.value.trim();
    S.password = passIn.value;
    await act(registerBtn, s1, async () => {
      const r = await call('POST', '/api/auth/register', { email: S.email, password: S.password });
      if (r.status === 202) say(s1, 'ok', `Accepted (HTTP 202) in ${ms(r)}, including one Argon2id hash. The service answers 202 whether or not the address already had an account, so it cannot be used to find out who has one.`);
      else if (r.json?.error?.code === 'password_rejected') {
        const why = (r.json.error.reasons || []).map((x) => REASONS[x] || x).join(' and ');
        say(s1, 'bad', `Passphrase refused (HTTP 422): ${why}. Use a longer phrase of ordinary words.`);
      } else say(s1, 'bad', describeLoginError(r));
    });
  }, 'btn-primary');

  const loginBtn = button('Sign in', async () => {
    S.email = emailIn.value.trim();
    S.password = passIn.value;
    await act(loginBtn, s1, async () => {
      const r = await call('POST', '/api/auth/login', { email: S.email, password: S.password });
      if (r.status === 200 && r.json.status === 'ok') {
        S.chain = [];
        S.mfaToken = null;
        await storeTokens(r.json);
        say(s1, 'ok', `Signed in (HTTP 200) in ${ms(r)}, including one Argon2id check. You now hold an access token and a refresh token.`);
      } else if (r.status === 200 && r.json.status === 'mfa_required') {
        S.mfaToken = r.json.mfa_token;
        S.access = null;
        say(s1, 'warn', `Password accepted, but this account has two-factor on, so no tokens were issued yet (status mfa_required). Finish in step 4.`);
      } else say(s1, 'bad', describeLoginError(r));
    });
  });

  const whoamiBtn = button('Call GET /api/me with the access token', async () => {
    await act(whoamiBtn, s1, async () => {
      const r = await call('GET', '/api/me', undefined, { auth: true });
      if (r.status === 200) say(s1, 'ok', 'Access token accepted (HTTP 200). The service says you are ', mono(r.json.email), `, role ${r.json.role}.`);
      else say(s1, 'bad', 'Refused (HTTP 401). Either the access token expired (they last 15 minutes of server time), or its session was revoked.');
    });
  });

  targets.push(() => {
    clear(tokensCard);
    if (!S.access) return;
    const jwt = decodeJwt(S.access);
    const c = jwt?.claims || {};
    tokensCard.append(
      h('h4', {}, 'Access token'),
      h('dl.kv', {},
        h('dt', {}, 'Algorithm'), h('dd', {}, `${jwt?.header.alg} (Ed25519), key ${jwt?.header.kid}`),
        h('dt', {}, 'Subject'), h('dd', {}, mono(String(c.sub).slice(0, 8))),
        h('dt', {}, 'Session'), h('dd', {}, mono(String(c.sid).slice(0, 8))),
        h('dt', {}, 'Role'), h('dd', {}, c.role),
        h('dt', {}, 'Method'), h('dd', {}, (c.amr || []).join(' + ') + (c.amr?.includes('otp') ? ' (two-factor)' : '')),
        h('dt', {}, 'Expires'), h('dd', {}, timeOf(c.exp * 1000) + ' server time')),
      h('details', {}, h('summary', {}, 'Show the full token'), h('pre.code', { tabindex: 0 }, S.access)),
      h('h4', {}, 'Refresh token'),
      h('p.small', {}, 'Opaque, random, single use. The service keeps only its SHA-256 hash.'),
      h('pre.code', { tabindex: 0 }, S.chain.at(-1)?.raw || ''));
  });
  targets.push(() => { whoamiBtn.disabled = !S.access; });

  // ---- step 2 and 3: rotate, replay ----------------------------------

  const s2 = resultBox();
  const s3 = resultBox();

  async function refreshWith(token, box, button_) {
    return act(button_, box, async () => {
      const r = await call('POST', '/api/auth/refresh', { refresh_token: token.raw });
      if (r.status === 200) {
        await storeTokens(r.json);
        say(box, 'ok', `New token pair issued (HTTP 200). The token you sent is now marked used and cannot be exchanged again.`);
      } else {
        const wasReuse = r.json?.error?.code === 'invalid_token';
        say(box, 'bad', `Refused (HTTP ${r.status}): ${r.json?.error?.message || 'error'}`, wasReuse ? ' The service does not say why. It never tells a caller whether a token was unknown, expired or reused.' : '');
      }
    });
  }

  const rotateBtn = button('Rotate the refresh token', () => refreshWith(S.chain.at(-1), s2, rotateBtn), 'btn-primary');
  const whoami2 = button('Call GET /api/me', async () => {
    await act(whoami2, s2, async () => {
      const r = await call('GET', '/api/me', undefined, { auth: true });
      if (r.status === 200) say(s2, 'ok', `Access token accepted (HTTP 200) for ${r.json.email}.`);
      else say(s2, 'bad', 'Refused (HTTP 401). The session behind this access token is no longer valid.');
    });
  });

  const replayBtn = button('Replay the oldest token', async () => {
    const old = S.chain[0];
    const gained = await refreshWith(old, s3, replayBtn);
    if (gained.includes('token_reuse_detected')) {
      clear(s3.querySelector('p'));
      s3.querySelector('p').append('Refused (HTTP 401), and the service recorded ', mono('token_reuse_detected'),
        '. Two parties held the same single-use token, so it revoked the whole session. Now try the newest token below: it was valid a moment ago.');
    }
  }, 'btn-danger');
  const newestBtn = button('Use the newest token', () => refreshWith(S.chain.at(-1), s3, newestBtn));
  const whoami3 = button('Call GET /api/me', async () => {
    await act(whoami3, s3, async () => {
      const r = await call('GET', '/api/me', undefined, { auth: true });
      if (r.status === 200) say(s3, 'ok', `Access token accepted (HTTP 200) for ${r.json.email}.`);
      else say(s3, 'bad', 'Refused (HTTP 401) straight away, although the access token has not expired. The service checks the session row on every request, so revoking a session takes effect at once.');
    });
  });

  targets.push(() => {
    const ready = S.chain.length > 0;
    rotateBtn.disabled = !ready;
    whoami2.disabled = !S.access;
    replayBtn.disabled = S.chain.length < 2;
    newestBtn.disabled = !ready;
    whoami3.disabled = !S.access;
  });

  // ---- step 4: two-factor --------------------------------------------

  const s4 = resultBox();
  const qrBox = h('div.qr');
  const standIn = h('div.standin');
  const codeIn = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '19', spellcheck: 'false', class: 'code-input' });
  const recoveryBox = h('div.recovery');
  let currentCode = null;

  const setupBtn = button('Start two-factor setup', async () => {
    await act(setupBtn, s4, async () => {
      const r = await call('POST', '/api/mfa/setup', {}, { auth: true });
      if (r.status !== 200) { say(s4, 'bad', `Refused (HTTP ${r.status}). Sign in first (step 1).`); return; }
      S.secret = r.json.secret;
      S.recovery = null;
      clear(qrBox).append(
        h('img', { alt: 'QR code for an authenticator app. The same secret is shown as text next to it.', width: '168', height: '168', src: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(r.json.qr_svg)}` }),
        h('p.small', {}, 'Secret: ', mono(S.secret)));
      say(s4, 'ok', `Setup started (HTTP 200). Two-factor stays off until you prove you can produce a code. Read it from the stand-in below, as you would from a phone.`);
      tick();
    });
  });

  async function tick() {
    if (!S.secret) { clear(standIn); currentCode = null; return; }
    let res;
    try { res = await host.totp(S.secret); } catch { return; }
    currentCode = res.code;
    const used = S.lastUsedCode === res.code;
    clear(standIn).append(
      h('p.label', {}, 'Authenticator stand-in'),
      h('p.otp', { 'aria-label': `Current code ${res.code.split('').join(' ')}` }, `${res.code.slice(0, 3)} ${res.code.slice(3)}`),
      h('p.small', {}, used ? `This code was already accepted. The service takes each code once; the next one comes in ${res.remaining} s.` : `Changes in ${res.remaining} s. A phone app would show the same digits.`),
      button('Copy into the code box', () => { codeIn.value = res.code; codeIn.focus(); }, 'btn-sm'));
  }
  authTimer = setInterval(() => { if (S.secret) tick(); }, 1000);

  const enableBtn = button('Turn on two-factor', async () => {
    await act(enableBtn, s4, async () => {
      const code = codeIn.value.trim();
      const r = await call('POST', '/api/mfa/enable', { code }, { auth: true });
      if (r.status === 200) {
        S.lastUsedCode = code;
        S.recovery = r.json.recovery_codes;
        codeIn.value = '';
        say(s4, 'ok', `Two-factor is on (HTTP 200). Ten recovery codes were issued and are shown once; the service stores only hashes. Now sign out and sign in again, using a fresh code.`);
      } else say(s4, 'bad', `${r.json?.error?.message || 'Refused'} (HTTP ${r.status}).`);
    });
  });

  const relogBtn = button('Sign out, then sign in again', async () => {
    await act(relogBtn, s4, async () => {
      await call('POST', '/api/auth/logout', undefined, { auth: true });
      S.access = null;
      const r = await call('POST', '/api/auth/login', { email: S.email, password: S.password });
      if (r.status === 200 && r.json.status === 'mfa_required') {
        S.mfaToken = r.json.mfa_token;
        say(s4, 'warn', 'Signed out. The password alone is no longer enough: the service answered mfa_required and issued no tokens. Enter a code to finish.');
      } else if (r.status === 200) {
        S.chain = [];
        await storeTokens(r.json);
        say(s4, 'warn', 'Signed in without a code, because two-factor is not on for this account yet.');
      } else say(s4, 'bad', describeLoginError(r));
    });
  });

  const finishBtn = button('Finish sign-in with the code', async () => {
    await act(finishBtn, s4, async () => {
      const code = codeIn.value.trim();
      const r = await call('POST', '/api/auth/login/mfa', { mfa_token: S.mfaToken, code });
      if (r.status === 200) {
        S.lastUsedCode = code;
        S.chain = [];
        S.mfaToken = null;
        codeIn.value = '';
        await storeTokens(r.json);
        say(s4, 'ok', `Signed in with two-factor (HTTP 200). The access token's method now includes otp.`);
      } else if (r.status === 401 && r.json?.error?.code === 'invalid_token') {
        S.mfaToken = null;
        say(s4, 'bad', 'That sign-in attempt expired (5 minutes of server time). Sign in again.');
      } else say(s4, 'bad', `${r.json?.error?.message || 'Refused'} (HTTP ${r.status}). A code works once, so a code you already used is refused. Wait for the next one, or use a recovery code.`);
    });
  });

  targets.push(() => {
    const live = sessionLive();
    setupBtn.disabled = !live;
    enableBtn.disabled = !S.secret || !live;
    relogBtn.disabled = !S.chain.length && !S.access;
    finishBtn.disabled = !S.mfaToken;
    clear(recoveryBox);
    if (S.recovery) {
      recoveryBox.append(h('p.label', {}, 'Recovery codes (shown once)'),
        h('ul.codes', {}, S.recovery.map((c) => h('li', {}, mono(c)))),
        h('p.small', {}, 'Any one of these works in place of an authenticator code, once.'));
    }
  });

  // ---- step 5: lockout -----------------------------------------------

  const s5 = resultBox();
  const targetSel = h('select', {},
    h('option', { value: 'seed' }, 'amina@example.com (seeded)'),
    h('option', { value: 'mine' }, 'the account from step 1'));
  const attempts = h('div.attempts');
  const seededPassword = () => app.host.info().accounts.find((a) => a.role === 'user').password;
  const target = () => (targetSel.value === 'seed'
    ? { email: 'amina@example.com', password: seededPassword() }
    : { email: S.email, password: S.password });

  function addAttempt(label, r, note) {
    let table = attempts.querySelector('tbody');
    if (!table) {
      clear(attempts).append(h('div.scroll-x', { tabindex: 0, role: 'region', 'aria-label': 'Login attempts' }, h('table.data', {},
        h('caption', {}, 'Attempts and what the service answered'),
        h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Attempt'), h('th', { scope: 'col' }, 'Answer'), h('th', { scope: 'col' }, 'Note'))),
        h('tbody'))));
      table = attempts.querySelector('tbody');
    }
    const answer = r.status === 200 ? '200 signed in' : r.status === 429 ? `429, wait ${r.retryAfter} s` : `${r.status} refused`;
    table.append(h('tr', { class: r.status === 429 ? 'is-alert' : r.status === 200 ? '' : 'is-warn' }, h('td', {}, label), h('td', {}, answer), h('td', {}, note || '')));
  }

  let attemptNo = 0;
  const wrongBtn = button('Send one wrong password', async () => {
    await act(wrongBtn, s5, async () => {
      const t = target();
      const r = await call('POST', '/api/auth/login', { email: t.email, password: 'not the right passphrase' });
      addAttempt(`Wrong password ${++attemptNo}`, r);
      say(s5, r.status === 429 ? 'warn' : 'bad', r.status === 429 ? `Blocked before the password was even checked (HTTP 429). Retry-After: ${r.retryAfter} s. Move the server clock forward, or press the button again later.` : `Refused (HTTP ${r.status}).`);
    });
  });

  const lockBtn = button('Fail until locked out', async () => {
    await act(lockBtn, s5, async () => {
      const t = target();
      let skipped = 0;
      for (let i = 0; i < 24; i += 1) {
        const r = await call('POST', '/api/auth/login', { email: t.email, password: 'not the right passphrase' });
        if (r.status === 429) {
          if (r.retryAfter >= 600) {
            addAttempt(`Wrong password ${++attemptNo}`, r, 'Locked out for 15 minutes.');
            say(s5, 'warn', `Locked out: the service now refuses ${t.email} for ${Math.round(r.retryAfter / 60)} minutes (HTTP 429), even with the right password. ${skipped} s of short backoff waits were skipped by moving the server clock.`);
            return;
          }
          const wait = r.retryAfter + 1;
          await host.advance(wait);
          skipped += wait;
          addAttempt('(backoff)', r, `Waited ${wait} s: the demo moved the server clock instead of making you wait.`);
        } else {
          addAttempt(`Wrong password ${++attemptNo}`, r);
        }
      }
      say(s5, 'bad', 'Stopped after 24 tries without a lockout.');
    });
  });

  const rightBtn = button('Send the right password', async () => {
    await act(rightBtn, s5, async () => {
      const t = target();
      const r = await call('POST', '/api/auth/login', { email: t.email, password: t.password });
      addAttempt('Right password', r);
      if (r.status === 200) say(s5, 'ok', 'Signed in (HTTP 200). The failure counter for the account was cleared.');
      else if (r.status === 429) say(s5, 'warn', `Still refused (HTTP 429), although the password is correct: the lockout holds for ${r.retryAfter} s more. Move the clock forward 16 minutes.`);
      else say(s5, 'bad', `Refused (HTTP ${r.status}).`);
    });
  });

  const skipBtn = button('Move clock +16 min', async () => {
    await app.advanceClock(16 * 60);
    say(s5, 'neutral', 'Server clock moved forward 16 minutes. The 15-minute lockout window has passed.');
  });

  // ---- assemble -------------------------------------------------------

  const list = h('ol.steps', {},
    step(1, 'Create an account and sign in',
      'Register, then sign in. The tokens come back in the response body, the way an API client would receive them.',
      h('div.fields', {}, field('Email', emailIn), field('Passphrase (invented, do not type a real one)', passIn)),
      h('div.actions', {}, registerBtn, loginBtn, whoamiBtn), s1, tokensCard),
    step(2, 'Rotate the refresh token',
      'Each refresh token works exactly once. Exchanging it returns a new pair and marks the old token used.',
      h('div.actions', {}, rotateBtn, whoami2), s2, chainTable()),
    step(3, 'Replay an old token and watch the session die',
      'Pretend a thief copied a token before you rotated it. Replay it: the service cannot tell the thief from you, so it ends the whole session.',
      h('div.actions', {}, replayBtn, newestBtn, whoami3), s3, chainTable()),
    step(4, 'Turn on two-factor and sign in with a code',
      'Enrol an authenticator, then sign in again. The password alone no longer yields tokens.',
      h('div.actions', {}, setupBtn),
      h('div.enrol', {}, qrBox, standIn),
      h('div.fields', {}, field('Code (6 digits, or a recovery code)', codeIn)),
      h('div.actions', {}, enableBtn, relogBtn, finishBtn), s4, recoveryBox),
    step(5, 'Guess passwords until the account locks',
      'The service counts failures per account and per address, slows down after five, and locks the account for 15 minutes after ten.',
      h('div.fields', {}, field('Account to attack', targetSel)),
      h('div.actions', {}, wrongBtn, lockBtn, rightBtn, skipBtn), s5, attempts));

  clear(root).append(list);
  redraw();

  return {
    redraw,
    reset() {
      S = DEFAULTS();
      emailIn.value = S.email;
      passIn.value = S.password;
      codeIn.value = '';
      attemptNo = 0;
      for (const box of root.querySelectorAll('.result')) { clear(box); box.className = 'result'; }
      clear(attempts);
      clear(qrBox);
      redraw();
      tick();
    },
    destroy() { clearInterval(authTimer); },
  };
}
