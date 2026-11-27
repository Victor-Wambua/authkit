import { h, icon, logo, toast, guard } from './dom.js';
import { api, login, loginMfa } from './api.js';
import { field, formAlert, describeError, passwordMeter } from './forms.js';

export const pending = { mfaToken: null };
export const env = { dev: false, demo: [] };

const DEMO = [
  { label: 'Fill demo user', email: 'amina@example.com', password: 'demo-amina-passphrase-2026' },
  { label: 'Fill demo admin', email: 'admin@example.com', password: 'demo-admin-passphrase-2026' },
];

function brandPanel() {
  const item = (ico, title, text) => h('li', {}, icon(ico), h('div', {}, h('strong', {}, title), text));
  return h('aside.brand-panel', { 'aria-label': 'About Authkit' },
    h('a.brand', { href: '#/signin' }, logo(36), 'Authkit'),
    h('div', {},
      h('p.brand-title', {}, 'Sign-in that stays safe when something leaks.'),
      h('p.lead', {}, 'A small authentication service you can host yourself. Hashing, tokens and two-factor done the careful way.')),
    h('ul.proof', {},
      item('key', 'Argon2id password hashing', 'Tuned on the server it runs on, upgraded quietly at login.'),
      item('flame', 'Refresh tokens that detect theft', 'Replay one and the whole session is revoked.'),
      item('shield', 'Two-factor with recovery codes', 'TOTP with replay protection, codes stored hashed.'),
      item('list', 'Every sensitive action is logged', 'Who, what, from where, readable by admins.')),
    h('p.brand-foot', {}, 'Portfolio build. Runs locally with synthetic sample data.'));
}

function authFrame(active, ...body) {
  const tabs = h('nav.tabs', { 'aria-label': 'Account' },
    h('a.tab', { href: '#/signin', 'aria-current': active === 'signin' ? 'page' : null }, 'Sign in'),
    h('a.tab', { href: '#/register', 'aria-current': active === 'register' ? 'page' : null }, 'Create account'));
  return h('div.auth', {},
    brandPanel(),
    h('main#main.auth-main', {},
      h('div.auth-card', {},
        h('a.brand.mobile-brand', { href: '#/signin' }, logo(32), 'Authkit'),
        active ? tabs : null,
        ...body)));
}

function heading(title, text) {
  return h('div.heading', {}, h('h1', { tabindex: '-1' }, title), text ? h('p', {}, text) : null);
}

function demoBox(emailField, pwField) {
  if (!env.dev) return null;
  return h('div.card.flat', {},
    h('div', {}, h('h3', {}, 'Demo mode'), h('p.desc', {}, window.__AUTHKIT_DEMO__ ? 'Seeded with synthetic accounts. Use these to look around.' : 'Seeded with synthetic accounts. Run make seed once, then use these.')),
    h('div.form-row', {}, ...DEMO.map((d) => h('button.btn.btn-secondary.btn-sm', {
      type: 'button',
      onclick: () => { emailField.value = d.email; pwField.value = d.password; pwField.input.focus(); },
    }, d.label))));
}

export function signInView() {
  const email = field({ label: 'Email', type: 'email', name: 'email', autocomplete: 'username', inputmode: 'email', spellcheck: false });
  const pw = field({ label: 'Password', type: 'password', name: 'password', autocomplete: 'current-password' });
  const alert = formAlert();
  const submit = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Sign in');
  const form = h('form.form', { novalidate: true }, alert.el, email.root, pw.root,
    h('div.form-row.between', {}, h('a.fineprint', { href: '#/forgot' }, 'Forgot your password?')),
    submit);
  form.addEventListener('submit', guard(submit, async () => {
    alert.hide();
    email.setError(''); pw.setError('');
    if (!email.value.trim()) { email.setError('Enter your email address.'); email.input.focus(); return; }
    if (!pw.value) { pw.setError('Enter your password.'); pw.input.focus(); return; }
    try {
      const result = await login(email.value.trim(), pw.value);
      if (result.mfaToken) { pending.mfaToken = result.mfaToken; location.hash = '#/mfa'; return; }
      location.hash = '#/app';
    } catch (err) {
      alert.show(describeError(err));
      pw.value = '';
      pw.input.focus();
    }
  }));
  return authFrame('signin',
    heading('Welcome back', 'Sign in to manage your account and devices.'),
    form,
    demoBox(email, pw),
    h('p.fineprint', {}, 'New here? ', h('a', { href: '#/register' }, 'Create an account'), '.'));
}

export function registerView() {
  const email = field({ label: 'Email', type: 'email', name: 'email', autocomplete: 'username', inputmode: 'email', spellcheck: false });
  const pw = field({ label: 'Password', type: 'password', name: 'password', autocomplete: 'new-password' });
  const meter = passwordMeter(() => pw.value);
  pw.input.addEventListener('input', meter.update);
  const alert = formAlert();
  const submit = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Create account');
  const holder = h('div', {});
  const form = h('form.form', { novalidate: true }, alert.el, email.root, pw.root, meter.root, submit);
  form.addEventListener('submit', guard(submit, async () => {
    alert.hide(); email.setError(''); pw.setError('');
    if (!email.value.trim()) { email.setError('Enter your email address.'); email.input.focus(); return; }
    try {
      const out = await api('/api/auth/register', { method: 'POST', token: false, body: { email: email.value.trim(), password: pw.value } });
      holder.replaceChildren(h('div.card', {}, h('div.alert.ok', { role: 'status' }, icon('check'), h('div', {}, h('b', {}, 'Check your inbox. '), out.message)),
        h('p.desc', {}, 'The email contains a single-use link that expires in 24 hours.'),
        env.dev ? h('a.btn.btn-secondary', { href: '#/mailbox' }, icon('inbox'), 'Open the dev mailbox') : null,
        h('a.btn.btn-primary', { href: '#/signin' }, 'Go to sign in')));
      form.hidden = true;
    } catch (err) {
      if (err.code === 'password_rejected') pw.setError(describeError(err));
      else if (err.code === 'invalid_email') email.setError(err.message);
      else alert.show(describeError(err));
    }
  }));
  return authFrame('register',
    heading('Create your account', 'Use a long passphrase. We check it against known breaches without sending it anywhere.'),
    form, holder,
    h('p.fineprint', {}, 'Already registered? ', h('a', { href: '#/signin' }, 'Sign in'), '.'));
}

export function forgotView() {
  const email = field({ label: 'Email', type: 'email', name: 'email', autocomplete: 'username', inputmode: 'email', spellcheck: false });
  const alert = formAlert();
  const submit = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Email me a reset link');
  const form = h('form.form', { novalidate: true }, alert.el, email.root, submit);
  form.addEventListener('submit', guard(submit, async () => {
    alert.hide();
    try {
      const out = await api('/api/auth/password/forgot', { method: 'POST', token: false, body: { email: email.value.trim() } });
      alert.show(out.message + (env.dev ? ' (Dev mode: open the mailbox to read it.)' : ''), 'ok');
    } catch (err) { alert.show(describeError(err)); }
  }));
  return authFrame(null,
    heading('Reset your password', 'We will email a single-use link if the address has an account. The answer is the same either way.'),
    form,
    h('p.fineprint', {}, h('a', { href: '#/signin' }, 'Back to sign in')));
}

export function resetView(route) {
  const token = route.query.get('token') || '';
  const pw = field({ label: 'New password', type: 'password', name: 'new-password', autocomplete: 'new-password' });
  const meter = passwordMeter(() => pw.value);
  pw.input.addEventListener('input', meter.update);
  const alert = formAlert();
  const submit = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Set new password');
  const form = h('form.form', { novalidate: true }, alert.el, pw.root, meter.root, submit);
  form.addEventListener('submit', guard(submit, async () => {
    alert.hide(); pw.setError('');
    try {
      await api('/api/auth/password/reset', { method: 'POST', token: false, body: { token, new_password: pw.value } });
      toast('Password updated. Sign in with the new one.');
      location.hash = '#/signin';
    } catch (err) {
      if (err.code === 'password_rejected') pw.setError(describeError(err));
      else alert.show(err.code === 'invalid_token' ? 'This link is invalid, expired or already used. Request a new one.' : describeError(err));
    }
  }));
  return authFrame(null,
    heading('Choose a new password', 'All devices will be signed out when you save it.'),
    token ? form : h('div.alert.danger', { role: 'alert' }, icon('alert'), h('div', {}, 'This page needs the link from your email.')),
    h('p.fineprint', {}, h('a', { href: '#/forgot' }, 'Request a new link')));
}

export function verifyView(route) {
  const token = route.query.get('token') || '';
  const box = h('div', { 'aria-live': 'polite' }, h('div.skeleton.h-48'));
  (async () => {
    try {
      await api('/api/auth/email/verify', { method: 'POST', token: false, body: { token } });
      box.replaceChildren(h('div.alert.ok', {}, icon('check'), h('div', {}, h('b', {}, 'Email confirmed. '), 'You can sign in now.')),
        h('p.mt', {}, h('a.btn.btn-primary', { href: '#/signin' }, 'Continue to sign in')));
    } catch {
      box.replaceChildren(h('div.alert.danger', { role: 'alert' }, icon('alert'), h('div', {}, 'This link is invalid, expired or already used. Sign in and use "Resend" on your overview page.')),
        h('p.mt', {}, h('a.btn.btn-secondary', { href: '#/signin' }, 'Back to sign in')));
    }
  })();
  return authFrame(null, heading('Confirming your email'), box);
}

export function mfaView() {
  if (!pending.mfaToken) { location.hash = '#/signin'; return h('div'); }
  let recovery = false;
  const code = field({ label: 'Authentication code', name: 'code', autocomplete: 'one-time-code', inputmode: 'numeric', hint: 'Open your authenticator app and enter the 6-digit code.', maxlength: 6, className: 'code', spellcheck: false });
  const alert = formAlert();
  const submit = h('button.btn.btn-primary.btn-block', { type: 'submit' }, 'Verify and sign in');
  const toggle = h('button.btn.btn-ghost.btn-sm', { type: 'button' }, 'Use a recovery code instead');
  toggle.addEventListener('click', () => {
    recovery = !recovery;
    const input = code.input;
    input.value = '';
    input.maxLength = recovery ? 19 : 6;
    input.inputMode = recovery ? 'text' : 'numeric';
    input.classList.toggle('code', !recovery);
    code.root.querySelector('label').textContent = recovery ? 'Recovery code' : 'Authentication code';
    code.root.querySelector('.hint').textContent = recovery ? 'Enter one of your saved codes, like ABCD-EFGH-JKLM-NPQR. Each works once.' : 'Open your authenticator app and enter the 6-digit code.';
    toggle.textContent = recovery ? 'Use my authenticator app instead' : 'Use a recovery code instead';
    input.focus();
  });
  const form = h('form.form', { novalidate: true }, alert.el, code.root, submit, toggle);
  form.addEventListener('submit', guard(submit, async () => {
    alert.hide(); code.setError('');
    try {
      await loginMfa(pending.mfaToken, code.value.trim());
      pending.mfaToken = null;
      location.hash = '#/app';
    } catch (err) {
      if (err.status === 401 && err.code === 'invalid_token') { pending.mfaToken = null; location.hash = '#/signin'; toast('That sign-in attempt timed out. Start again.', 'error'); return; }
      alert.show(describeError(err));
      code.value = ''; code.input.focus();
    }
  }));
  return authFrame(null,
    heading('Two-factor authentication', 'Your password was correct. One more step.'),
    form,
    h('p.fineprint', {}, h('a', { href: '#/signin', onclick: () => { pending.mfaToken = null; } }, 'Cancel and start over')));
}
