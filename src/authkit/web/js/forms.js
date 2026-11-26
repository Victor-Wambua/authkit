import { h, icon } from './dom.js';

let uid = 0;

/** A labelled input with hint and inline error wired up for screen readers. */
export function field({ label, type = 'text', name, autocomplete, hint, required = true, value = '', inputmode, placeholder, maxlength, spellcheck, className = '' }) {
  const id = `f${++uid}`;
  const input = h('input.input' + (className ? '.' + className : ''), {
    id, name, type, autocomplete, required, value, inputmode, placeholder, maxlength,
    spellcheck: spellcheck === undefined ? undefined : String(spellcheck),
    autocapitalize: 'off', autocorrect: 'off',
  });
  const hintEl = hint ? h('div.hint', { id: `${id}-hint` }, hint) : null;
  const errorEl = h('div.error', { id: `${id}-err`, hidden: true, role: 'alert' });
  input.setAttribute('aria-describedby', [hint ? `${id}-hint` : '', `${id}-err`].filter(Boolean).join(' '));

  let control = input;
  if (type === 'password') {
    const reveal = h('button.reveal', { type: 'button', 'aria-label': 'Show password', 'aria-pressed': 'false' }, icon('eye'));
    reveal.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      reveal.setAttribute('aria-pressed', String(show));
      reveal.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      reveal.replaceChildren(icon(show ? 'eyeOff' : 'eye'));
    });
    control = h('div.input-wrap', {}, input, reveal);
  }

  const root = h('div.field', {}, h('label', { for: id }, label), control, hintEl, errorEl);
  return {
    root,
    input,
    get value() { return input.value; },
    set value(v) { input.value = v; },
    setError(message) {
      errorEl.replaceChildren();
      errorEl.hidden = !message;
      if (message) {
        errorEl.append(icon('alert'), h('span', {}, message));
        input.setAttribute('aria-invalid', 'true');
      } else {
        input.removeAttribute('aria-invalid');
      }
    },
  };
}

export function formAlert() {
  const el = h('div', { role: 'alert', hidden: true });
  return {
    el,
    show(message, tone = 'danger') {
      el.className = `alert ${tone}`;
      el.hidden = false;
      el.replaceChildren(icon(tone === 'ok' ? 'check' : 'alert'), h('div', {}, message));
    },
    hide() { el.hidden = true; el.replaceChildren(); },
  };
}

const POLICY_MESSAGES = {
  too_short: 'Use at least 12 characters. A few random words in a row works well.',
  too_long: 'That is longer than 128 characters.',
  contains_email: 'Leave your email address out of your password.',
  repetitive_or_sequential: 'Avoid repeated or sequential characters such as aaaa or 12345.',
  breached: 'This password appears in a list of breached passwords. Choose a different one.',
};

export function describeError(err) {
  if (!err || !err.code) return 'Something went wrong. Check your connection and try again.';
  if (err.code === 'password_rejected') {
    return (err.data.reasons || []).map((r) => POLICY_MESSAGES[r] || r).join(' ');
  }
  if (err.code === 'too_many_attempts') {
    const secs = err.data.retryAfter || err.data.retry_after;
    return `Too many attempts. Try again ${secs ? 'in ' + formatWait(secs) : 'later'}.`;
  }
  return err.message;
}

function formatWait(seconds) {
  if (seconds < 90) return `${seconds} seconds`;
  return `${Math.ceil(seconds / 60)} minutes`;
}

/** A length-first strength hint. It claims nothing beyond length: the server does the real checks. */
export function passwordMeter(getValue) {
  const bar = h('i');
  const meter = h('div.meter', { role: 'presentation' }, bar);
  const text = h('div.hint', { 'aria-live': 'polite' }, 'At least 12 characters. Length matters more than symbols.');
  function update() {
    const n = [...getValue()].length;
    const level = n >= 16 ? 'good' : n >= 12 ? 'ok' : 'low';
    meter.dataset.level = level;
    bar.style.width = `${Math.min(100, (n / 20) * 100)}%`;
    text.textContent = n === 0
      ? 'At least 12 characters. Length matters more than symbols.'
      : level === 'low' ? `${n} characters. ${12 - n} more to go.`
      : level === 'ok' ? `${n} characters. Long enough; more is better.`
      : `${n} characters. Nice and long.`;
  }
  update();
  return { root: h('div.meter-wrap', {}, meter, text), update };
}
