// Local browser checks with synthetic accounts only; no real server is used.
// Requires Playwright. Run from the repository root with node backend/panel-tests/admin-panel.cjs.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const assert = require('node:assert/strict');

(async () => {
  const assets = path.join(__dirname, '../internal/httpapi/panel');
  const accounts = [
    { account_id: 'owner', email: 'owner@example.test', role: 'admin', created_at: '2026-10-12T12:00:00Z' },
    { account_id: 'friend', email: 'friend@example.test', role: 'user', created_at: '2026-10-12T12:00:00Z' }
  ];
  let invitations = 0, deletions = 0;
  const server = http.createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.url.startsWith('/api/')) {
      if (req.headers.authorization !== 'Bearer test-key') return send(401, { code: 'admin_access_denied' });
      if (req.method === 'GET') return send(200, { items: accounts, next_after: null });
      let raw = ''; for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      if (req.url.endsWith('/invitations')) {
        if (accounts.some(a => a.email === body.email)) return send(409, { code: 'account_exists' });
        invitations++; return send(201, { email: body.email, invitation_secret: 'synthetic-one-time-code', expires_at: '2026-10-13T12:00:00Z' });
      }
      assert.equal(body.confirm_email, 'friend@example.test');
      assert.equal(body.account_id, 'friend');
      accounts.splice(1, 1); deletions++; res.writeHead(204); return res.end();
    }
    const filename = { '/admin': 'index.html', '/admin/app.js': 'app.js', '/admin/style.css': 'style.css', '/brand.png': 'logo.png' }[req.url];
    if (!filename) { res.writeHead(404); return res.end(); }
    const type = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png' }[path.extname(filename)];
    res.writeHead(200, { 'Content-Type': type + (type === 'image/png' ? '' : '; charset=utf-8') });
    res.end(fs.readFileSync(path.join(assets, filename)));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    const executable = process.env.BYTELOCKER_BROWSER;
    browser = await chromium.launch({ headless: true, ...(executable ? { executablePath: executable } : {}) });
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto('http://127.0.0.1:' + server.address().port + '/admin');
    await page.locator('#key').fill('test-key'); await page.getByRole('button', { name: 'Accedi al pannello' }).click();
    await page.locator('#accounts').waitFor({ state: 'visible' });
    assert.equal(await page.getByRole('button', { name: 'Elimina account owner@example.test' }).count(), 0);
    await page.locator('#email').fill('new@example.test'); await page.getByRole('button', { name: 'Genera invito' }).click();
    await page.locator('#invitation-result').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#invitation-code').inputValue(), 'synthetic-one-time-code'); assert.equal(invitations, 1);
    await page.locator('#email').fill('owner@example.test'); await page.getByRole('button', { name: 'Genera invito' }).click();
    await page.getByText('Questa email ha già un account sul server.', { exact: true }).waitFor();
    assert.equal(await page.locator('#invitation-code').inputValue(), '');
    await page.getByRole('button', { name: 'Elimina account friend@example.test' }).click();
    assert.equal(await page.locator('#confirm-delete').isDisabled(), true);
    await page.locator('#confirm-email').fill('wrong@example.test'); assert.equal(await page.locator('#confirm-delete').isDisabled(), true);
    await page.getByRole('button', { name: 'Annulla' }).click(); assert.equal(deletions, 0);
    await page.getByRole('button', { name: 'Elimina account friend@example.test' }).click();
    await page.locator('#confirm-email').fill('friend@example.test'); assert.equal(await page.locator('#confirm-delete').isEnabled(), true);
    await page.getByRole('button', { name: 'Elimina definitivamente' }).click();
    await page.getByText('Account eliminato. Sessioni e vault cifrato rimossi dal server.', { exact: true }).waitFor();
    assert.equal(deletions, 1); assert.equal(await page.locator('#rows tr').count(), 1);
    const preview = process.env.BYTELOCKER_PREVIEW_DIR;
    if (preview) await page.screenshot({ path: path.join(preview, 'admin-0.2.2-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    if (preview) await page.screenshot({ path: path.join(preview, 'admin-0.2.2-mobile.png'), fullPage: true });
    await page.getByRole('button', { name: 'Esci', exact: true }).click();
    assert.equal(await page.locator('#accounts').isVisible(), false); assert.equal(await page.locator('#rows tr').count(), 0);
    assert.equal(await page.locator('#invitation-code').inputValue(), ''); assert.deepEqual(errors, []);
    console.log('Panel browser checks passed: invitation, errors, confirmation, cancellation, deletion, protected admin, mobile layout and logout.');
  } finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });
