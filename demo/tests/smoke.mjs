// Headless-browser smoke test of the demo: runs the real service in Pyodide and drives the
// walkthrough, the framed web app, reset and offline reload.
//
//   python3 demo/build.py && node demo/tests/smoke.mjs
//
// Optional environment: PORT (default 8905), CHROME_PATH (a Chromium binary) and
// PLAYWRIGHT_MODULE (path to playwright's index.mjs when it is not installed locally).
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const DIST = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'dist');
const PORT = Number(process.env.PORT || 8905);
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.wasm': 'application/wasm', '.zip': 'application/zip', '.svg': 'image/svg+xml', '.txt': 'text/plain', '.whl': 'application/octet-stream' };

const server = createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '');
  try {
    const file = path.endsWith('/') ? join(DIST, path, 'index.html') : join(DIST, path);
    const body = await readFile(file);
    res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(PORT);

const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined });
let failures = 0;
const log = [];

async function run(name, fn) {
  try {
    await fn();
    log.push(`ok   ${name}`);
  } catch (err) {
    failures += 1;
    if (process.env.SHOTS) await page.screenshot({ path: join(process.env.SHOTS, `fail-${failures}.png`), fullPage: true }).catch(() => {});
    log.push(`FAIL ${name}\n     ${String(err.message).split('\n')[0]}`);
  }
}

const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const page = await context.newPage();
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push(e.message));

const url = `http://localhost:${PORT}/`;
await page.goto(url);
await page.waitForSelector('#grid:not([hidden])', { timeout: 90_000 });

const step = (n) => page.locator(`#step-${n}`).locator('xpath=ancestor::li[1]');
const result = (n) => step(n).locator('.result');
const auditText = () => page.locator('#audit').innerText();
const auditHas = async (event, who) => (await page.locator('#audit tbody tr', { hasText: event }).filter({ hasText: who }).count()) > 0;
const click = (n, name) => step(n).getByRole('button', { name, exact: true }).click();

await run('page basics: one h1, banner, landmarks, title', async () => {
  assert.equal(await page.locator('h1').count(), 1);
  assert.match(await page.locator('#banner').innerText(), /Static demo\. Runs in your browser on invented data; nothing is sent anywhere/);
  for (const sel of ['header', 'main', 'aside', 'footer']) assert.equal(await page.locator(sel).count() >= 1, true, sel);
  assert.match(await page.title(), /walkthrough/);
  assert.match(await auditText(), /login_failure/, 'seed audit rows are shown on load');
});

await run('register and sign in return tokens', async () => {
  await click(1, 'Create account');
  await result(1).getByText('Accepted (HTTP 202)').waitFor();
  await click(1, 'Sign in');
  await result(1).getByText('Signed in (HTTP 200)').waitFor();
  await step(1).getByText('Ed25519').waitFor();
  assert.match(await auditText(), /register/);
  assert.ok(await auditHas('login_success', 'visitor@example.test'));
});

await run('rotation marks the old token used', async () => {
  await click(2, 'Rotate the refresh token');
  await result(2).getByText('New token pair issued').waitFor();
  const rows = step(2).locator('.chain tbody tr');
  assert.equal(await rows.count(), 2);
  assert.match(await rows.nth(0).innerText(), /used/);
  assert.match(await rows.nth(1).innerText(), /current/);
});

await run('replaying an old token revokes the whole session', async () => {
  await click(3, 'Replay the oldest token');
  await result(3).getByText('token_reuse_detected').first().waitFor();
  const rows = step(3).locator('.chain tbody tr');
  for (let i = 0; i < 2; i += 1) assert.match(await rows.nth(i).innerText(), /revoked \(token_reuse\)/);
  await click(3, 'Use the newest token');
  await result(3).getByText('Refused (HTTP 401)').first().waitFor();
  await step(3).getByRole('button', { name: 'Call GET /api/me' }).click();
  await result(3).getByText('straight away').waitFor();
  assert.ok(await auditHas('token_reuse_detected', 'visitor@example.test'));
});

await run('two-factor: enrol, code replay refused, sign in with a fresh code', async () => {
  await click(1, 'Sign in');
  await result(1).getByText('Signed in (HTTP 200)').waitFor();
  await click(4, 'Start two-factor setup');
  await step(4).locator('.standin .otp').waitFor();
  const first = (await step(4).locator('.standin .otp').innerText()).replace(/\s/g, '');
  await step(4).getByRole('button', { name: 'Copy into the code box' }).click();
  await click(4, 'Turn on two-factor');
  await result(4).getByText('Two-factor is on').waitFor();
  assert.equal(await step(4).locator('.codes li').count(), 10);
  await click(4, 'Sign out, then sign in again');
  await result(4).getByText('mfa_required').waitFor();
  await step(4).locator('input.code-input').fill(first);
  await click(4, 'Finish sign-in with the code');
  await result(4).getByText('A code works once').waitFor();
  await page.locator('#adv-15').click(); // next 30 s window, and the old sign-in attempt expires
  await click(4, 'Sign out, then sign in again');
  await result(4).getByText('mfa_required').waitFor();
  await page.waitForFunction((old) => {
    const el = document.querySelector('#step-4')?.closest('li')?.querySelector('.standin .otp');
    return el && el.textContent.replace(/\s/g, '') !== old;
  }, first);
  await step(4).getByRole('button', { name: 'Copy into the code box' }).click();
  await click(4, 'Finish sign-in with the code');
  await result(4).getByText('Signed in with two-factor').waitFor();
  assert.match(await auditText(), /totp_enabled/);
  assert.match(await auditText(), /login_password_ok_mfa_pending/);
});

await run('lockout after repeated failures, held for a correct password, released by the clock', async () => {
  await click(5, 'Fail until locked out');
  await result(5).getByText('Locked out').waitFor({ timeout: 60_000 });
  await click(5, 'Send the right password');
  await result(5).getByText('Still refused (HTTP 429)').waitFor();
  await click(5, 'Move clock +16 min');
  await click(5, 'Send the right password');
  await result(5).getByText('Signed in (HTTP 200)').waitFor();
  assert.match(await auditText(), /login_blocked/);
});

await run('web app tab: the repository UI signs in against the in-page service', async () => {
  await page.getByRole('tab', { name: 'Web app' }).click();
  assert.match(await page.title(), /web app/);
  const frame = page.frameLocator('#app-frame');
  await frame.getByRole('button', { name: 'Fill demo user' }).click();
  await frame.getByRole('button', { name: 'Sign in' }).click();
  await frame.getByText('Signed in as amina@example.com').waitFor();
  await page.getByRole('tab', { name: 'Walkthrough' }).click();
  assert.match(await page.locator('#wire').innerText(), /\/api\/auth\/login[\s\S]*web app/);
});

await run('keyboard: tabs move with arrow keys', async () => {
  await page.getByRole('tab', { name: 'Walkthrough' }).focus();
  await page.keyboard.press('ArrowRight');
  assert.equal(await page.getByRole('tab', { name: 'Web app' }).getAttribute('aria-selected'), 'true');
  await page.keyboard.press('ArrowLeft');
  assert.equal(await page.getByRole('tab', { name: 'Walkthrough' }).getAttribute('aria-selected'), 'true');
});

await run('reset restores the seed data', async () => {
  await page.locator('#reset').click();
  await page.waitForFunction(() => document.querySelectorAll('#audit tbody tr').length === 5);
  assert.doesNotMatch(await auditText(), /visitor@example\.test/);
  assert.equal(await step(2).locator('.chain tbody tr').count(), 0);
});

await run('no page errors', async () => assert.deepEqual(pageErrors, []));

await run('works offline after one visit', async () => {
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.waitForFunction(async () => (await caches.keys()).length > 0 && (await (await caches.open((await caches.keys())[0])).keys()).length > 25, null, { timeout: 90_000 });
  await context.setOffline(true);
  await page.reload();
  await page.waitForSelector('#grid:not([hidden])', { timeout: 90_000 });
  await click(1, 'Create account');
  await result(1).getByText('Accepted (HTTP 202)').waitFor();
  await context.setOffline(false);
});

await browser.close();
server.close();
console.log(log.join('\n'));
if (failures) {
  console.error(`${failures} check(s) failed`);
  process.exit(1);
}
console.log(`all ${log.length} checks passed`);
