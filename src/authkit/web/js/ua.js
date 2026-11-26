// Minimal user-agent summary for the sessions list. Good enough for a label, not for security.
export function describeAgent(ua) {
  if (!ua) return { name: 'Unknown device', kind: 'monitor' };
  const lower = ua.toLowerCase();
  let os = 'Unknown OS';
  let kind = 'monitor';
  if (/iphone|ipad/.test(lower)) { os = 'iOS'; kind = 'phone'; }
  else if (/android/.test(lower)) { os = 'Android'; kind = /mobile/.test(lower) ? 'phone' : 'monitor'; }
  else if (/windows/.test(lower)) os = 'Windows';
  else if (/mac os x|macintosh/.test(lower)) os = 'macOS';
  else if (/linux|x11/.test(lower)) os = 'Linux';
  let browser = 'Browser';
  if (/^curl\//.test(lower)) { return { name: 'curl', kind: 'terminal' }; }
  if (/python-requests|httpx|okhttp|postman/.test(lower)) { return { name: ua.split(' ')[0], kind: 'terminal' }; }
  if (/edg\//.test(lower)) browser = 'Edge';
  else if (/firefox|fxios/.test(lower)) browser = 'Firefox';
  else if (/chrome|crios|headlesschrome/.test(lower)) browser = 'Chrome';
  else if (/safari/.test(lower)) browser = 'Safari';
  return { name: `${browser} on ${os}`, kind };
}

const EVENT_LABELS = {
  register: ['Account created', 'user', ''],
  register_duplicate: ['Sign-up attempt for an existing address', 'info', ''],
  login_success: ['Signed in', 'check', 'ok'],
  login_failure: ['Failed sign-in', 'alert', 'danger'],
  login_blocked: ['Sign-in blocked: too many attempts', 'lock', 'danger'],
  login_password_ok_mfa_pending: ['Password accepted, waiting for 2FA code', 'key', ''],
  mfa_failure: ['Wrong two-factor code', 'alert', 'danger'],
  mfa_blocked: ['Two-factor attempts blocked', 'lock', 'danger'],
  logout: ['Signed out', 'logout', ''],
  password_changed: ['Password changed', 'key', 'ok'],
  password_rehashed: ['Password hash upgraded to current settings', 'refresh', ''],
  password_reset_requested: ['Password reset requested', 'mail', ''],
  password_reset_completed: ['Password reset, all sessions signed out', 'key', 'ok'],
  email_verified: ['Email address confirmed', 'mail', 'ok'],
  totp_enabled: ['Two-factor authentication turned on', 'shield', 'ok'],
  totp_disabled: ['Two-factor authentication turned off', 'shield', 'danger'],
  recovery_code_used: ['Recovery code used', 'key', 'danger'],
  recovery_codes_regenerated: ['Recovery codes replaced', 'refresh', ''],
  token_reuse_detected: ['Refresh token reuse detected: session revoked', 'flame', 'danger'],
  session_revoked: ['Session revoked', 'logout', ''],
  other_sessions_revoked: ['Signed out other devices', 'logout', ''],
  account_deleted: ['Account deleted', 'trash', 'danger'],
};

export function describeEvent(name) {
  const [label, icon, tone] = EVENT_LABELS[name] || [name.replaceAll('_', ' '), 'info', ''];
  return { label, icon, tone };
}

export const EVENT_NAMES = Object.keys(EVENT_LABELS);
