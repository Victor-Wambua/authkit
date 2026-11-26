# Threat model

A STRIDE-style walk through what Authkit protects, what it does about each threat, and what is left over. It is a design review by the author, not an external audit. "Residual risk" is where I say what the mitigation does *not* cover.

**Scope.** One Authkit process behind TLS you provide, SQLite on local disk, a mail relay you provide, browsers and API clients as callers. **Attacker models:** (1) an anonymous internet attacker; (2) a user with a valid account attacking others; (3) someone who obtains a copy of the database; (4) someone who steals one refresh or access token; (5) someone who can read server logs.

## Assets

| Asset | Why it matters |
|---|---|
| Password hashes | A dump lets an attacker guess passwords offline |
| Refresh tokens | Long-lived: whoever holds one is the user until it is revoked |
| Access tokens | Short-lived bearer credential |
| JWT signing keys, data key, pepper (`keys.json`) | Forge tokens; decrypt TOTP secrets; attack recovery codes |
| TOTP secrets and recovery codes | Second factor; recovery codes bypass it |
| Audit log | Evidence after an incident; also personal data (IP, user agent) |
| Mailbox of the user | Reset and verification links grant account control |
| Availability of sign-in | Lockout and hashing cost can be turned against users |

## Threats and mitigations

| # | Asset | STRIDE | Threat | Mitigation | Residual risk |
|---|---|---|---|---|---|
| 1 | Password hashes | Information disclosure | Database dump, offline cracking | Argon2id, 64 MiB, t=3, per-hash salt; length-first policy; breached-password check at registration, change and reset | Weak passwords not in the breach list still fall to a determined attacker. The check is not repeated for existing users |
| 2 | Password hashes | Information disclosure | Hash parameters age as hardware improves | `needs_rehash` on every successful login upgrades the stored hash | Accounts that never log in keep old parameters |
| 3 | Login | Spoofing | Credential stuffing, online guessing | Per-account and per-IP sliding window, exponential backoff, temporary lockout, all clock-tested; breach check; optional 2FA | Distributed attacks stay under per-IP limits. No CAPTCHA, no device reputation |
| 4 | Login | Denial of service | Attacker locks a victim out by failing on purpose | Blocked attempts are not counted (the lockout cannot be extended by hammering); per-IP limits are separate; password reset clears the account lockout | A determined attacker can still keep one account locked in cycles. An unlock action for admins is not built |
| 5 | Login | Information disclosure | User enumeration through responses | Registration, reset and login give one status and body for known and unknown addresses; throttling applies to unknown addresses too | Mail is sent only to real addresses, so the *mailbox owner* learns about attempts. Password-policy errors on registration are shown, but they do not depend on whether the account exists |
| 6 | Login | Information disclosure | User enumeration through timing | Unknown or inactive accounts verify against a dummy Argon2 hash; registration hashes on both paths; mail is sent in a background task. Measured: known vs unknown login medians within about 1 ms across two runs | Database lookups and other small differences are not eliminated. A statistical attacker with many samples may still see something. Not proven constant-time |
| 7 | Refresh token | Spoofing / elevation | Stolen refresh token replayed | Single-use rotation. A replayed token revokes the whole session family, signs the real user out, and writes `token_reuse_detected` to the audit log | If the thief rotates first, the *victim's* next refresh is the detected reuse: detection happens at the second use, not the first |
| 8 | Refresh token | Information disclosure | Token read from the database | Stored only as SHA-256 of 256-bit random values | A dump plus a live server is not enough to mint tokens, but attackers with write access to the DB can create sessions |
| 9 | Refresh token | Tampering | Race: two parallel refreshes | Compare-and-swap `UPDATE ... WHERE used_at IS NULL` inside a `BEGIN IMMEDIATE` transaction. Tested with 8 racing threads: one winner | A legitimate double refresh (two tabs) looks like reuse and signs that device out. No grace window by design |
| 10 | Access token | Spoofing | Forged or altered JWT | Algorithm taken from the key, not the header; `alg: none` and HMAC-with-public-key confusion rejected; `iss`, `aud`, `exp` and token purpose checked; tamper test | A leaked signing key forges tokens until rotated |
| 11 | Access token | Elevation | Stolen access token used for 15 minutes | Short life; authenticated endpoints also check that the session is not revoked and the user is active, so revocation is immediate here; password, 2FA-disable and delete need re-authentication | A resource server that verifies the JWT offline will honour it until expiry |
| 12 | Signing keys / data key | Information disclosure | Key file read from disk or backup | File mode 600 enforced in production; keys kept separate from the DB; `kid` rotation and pruning; TOTP secrets encrypted with a Fernet data key | Keys sit on the same host as the process. No HSM or secrets manager integration. Losing the data key loses all 2FA secrets |
| 13 | TOTP | Spoofing | Code guessing or reuse | Per-user throttle on second-factor attempts; ±1 step window; a step at or before the last used one is rejected (atomic update); secrets encrypted at rest | Real-time phishing of password and code together. Anyone who steals the secret during enrolment |
| 14 | Recovery codes | Spoofing | Offline guessing from a dump | 80-bit codes, HMAC-SHA-256 with a server pepper, single use, replaced on regeneration; use is audited | Pepper and DB together allow offline guessing of the remaining space (still 2^80) |
| 15 | Reset / verify links | Spoofing | Guessed, replayed or leaked links | 256-bit random, stored hashed, single use, 1 h (reset) / 24 h (verify) expiry; new request voids the old one; purpose-bound; token travels in the URL fragment (not sent to servers or `Referer`); reset signs out all sessions and notifies by mail | Anyone with the user's mailbox owns the account. No second check on reset for accounts with 2FA (a reset keeps 2FA enabled but does not require it) |
| 16 | Audit log | Repudiation | Actions with no record; log editing | Security events written in the same transaction as the change; admin-only read endpoint; secrets never stored (tested) | Plain table: a DB admin can edit it. No hash chain, no off-box shipping. Failed-login rows store the attempted address, which can be mistyped password text |
| 17 | Audit log / users | Information disclosure | Personal data kept after deletion | Account deletion removes user, sessions, tokens and codes | Audit rows (user id, IP, user agent) stay. A real deployment needs a retention rule and a data-protection review |
| 18 | Logs | Information disclosure | Passwords or tokens in logs | JSON logs with key-based and pattern-based redaction (passwords, JWTs, `rt_`/`et_` tokens, bearer headers, recovery codes); query strings are not logged; validation errors do not echo input | Pattern redaction is best effort. A new secret field with an unusual name would need adding |
| 19 | HTTP surface | Tampering | XSS, clickjacking, MIME sniffing | CSP with no inline script or style and no `unsafe-eval`; `frame-ancestors 'none'`; `nosniff`; DOM built with `textContent`; QR SVG parsed and stripped before insertion | The relaxed CSP on `/docs` (inline styles) when docs are on. Docs are off in production by default |
| 20 | Browser sessions | Tampering | CSRF on refresh and logout | Cookie mode needs the `X-Auth-Mode` header (cross-site forms cannot set it) plus `SameSite=Strict`; bearer tokens are not ambient | Subdomain takeover or a compromised sibling origin |
| 21 | Browser sessions | Information disclosure | Token theft by script | Access token in memory only; refresh token in an `HttpOnly` cookie | XSS can still *use* the session while the page is open |
| 22 | HTTP surface | Denial of service | Huge bodies; expensive hashing | Body limit (64 KiB default) enforced on the declared length and on streamed bytes; password length capped | Each login costs ~64 MiB and ~70 ms of CPU. A flood of logins can exhaust a small host. No global concurrency limit |
| 23 | Client IP | Spoofing | Forged `X-Forwarded-For` to dodge per-IP limits | Header ignored unless `TRUSTED_PROXY_HOPS` is set; then the entry N hops from the right is used; invalid values fall back to the socket address | Misconfigured hop count either trusts attacker input or throttles the proxy itself. Behind a CDN the real address needs its own header handling |
| 24 | Privilege | Elevation | Self-registering as admin | Request models reject unknown fields; the role is read from the database on every request; admins are created only through the CLI | A DB write grants admin. No admin MFA requirement is enforced |
| 25 | Data store | Tampering / availability | SQLite on one disk | Transactions are serialised (`BEGIN IMMEDIATE`), WAL, foreign keys on | Single node, no replication, no encryption at rest (use disk encryption) |

## Out of scope (not built, and not claimed)

- **WebAuthn / passkeys.** The strongest answer to phishing. Not implemented.
- **Rate limiting behind proxies.** Per-IP limits are only as good as the address Authkit sees. Terminate TLS and set the hop count deliberately, or limit at the proxy.
- **TLS.** Run behind a TLS terminator. HSTS is sent outside dev mode.
- **Volumetric DoS, bot management, CAPTCHA, WAF.**
- **Account takeover by compromised mailboxes, SIM swap or social engineering.**
- **Multi-node deployments, per-tenant isolation, SSO/OIDC provider features.**
- **Compliance claims.** Nothing here has been assessed against SOC 2, ISO 27001 or any privacy law.
- **Backups and key escrow.** Losing `keys.json` invalidates all sessions and 2FA secrets.
