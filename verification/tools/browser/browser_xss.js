/**
 * Headless browser execution evidence for the XSS samples.
 *
 * A single authenticated DVWA session is reused (the security cookie is changed
 * per case).  A benign marker is written into the DOM by the injected handler;
 * the marker is only considered executed when the page's JS context reports it.
 * Reflection in the raw HTML is recorded separately.
 */
const { chromium } = require('playwright-core');
const fs = require('fs');
const path = require('path');

const BASE = 'http://127.0.0.1:9080';
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const ROOT = path.resolve(__dirname, '..', '..', '..');
const EVIDENCE = path.join(ROOT, 'verification', 'evidence');

function payloadFor(marker) {
  return `<svg onload="window.__wp4xss='${marker}';document.title='${marker}'">`;
}

function runIdFor(sample, level) {
  const number = sample.split('-')[1].toLowerCase();
  return `wp4-20261019-xss${number}-${level}`;
}

async function login(page) {
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await page.goto(`${BASE}/login.php`, { waitUntil: 'commit' });
    await page.fill('input[name="username"]', 'admin');
    await page.fill('input[name="password"]', 'password');
    await page.click('input[name="Login"]');
    await page.waitForTimeout(1200);
    const body = await page.content();
    if (page.url().includes('/index.php') || body.includes('You have logged in as')) {
      return true;
    }
    console.error(`login attempt ${attempt} failed: ${page.url()}`);
  }
  return false;
}

async function setSecurity(page, level) {
  await page.evaluate((lvl) => {
    document.cookie = `security=${lvl}; path=/`;
  }, level);
  await page.waitForTimeout(100);
}

async function record(runId, data, page, logs, errors) {
  const dir = path.join(EVIDENCE, runId);
  fs.mkdirSync(dir, { recursive: true });
  const screenshot = path.join(dir, 'browser.png');
  let screenshotRel = null;
  try {
    await page.screenshot({ path: screenshot, fullPage: false, timeout: 10000 });
    screenshotRel = path.relative(ROOT, screenshot).replace(/\\/g, '/');
  } catch (err) {
    errors.push(`screenshot: ${String(err)}`);
  }
  const result = {
    run_id: runId,
    ...data,
    console: logs,
    page_errors: errors,
    screenshot: screenshotRel,
    recorded_at: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(dir, 'browser.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify({
    run_id: runId,
    executed: data.executed,
    marker_in_raw_html: data.marker_in_raw_html,
    encoded_output_observed: data.encoded_output_observed,
    screenshot: result.screenshot,
  }));
}

async function main() {
  const browser = await chromium.launch({
    executablePath: CHROME,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  page.setDefaultNavigationTimeout(20000);
  const logs = [];
  const errors = [];
  page.on('console', (msg) => logs.push({ type: msg.type(), text: msg.text() }));
  page.on('pageerror', (err) => errors.push(String(err)));
  try {
    const loggedIn = await login(page);
    if (!loggedIn) {
      throw new Error('could not establish authenticated DVWA session');
    }
    console.log(JSON.stringify({ logged_in: true, url: page.url() }));

    for (const [sample, level, marker] of [
      ['XSS-001', 'low', 'WP4XSS001'],
      ['XSS-002', 'medium', 'WP4XSS002'],
      ['XSS-003', 'high', 'WP4XSS003'],
    ]) {
      await setSecurity(page, level);
      const payload = payloadFor(marker);
      const url = `${BASE}/vulnerabilities/xss_r/?name=${encodeURIComponent(payload)}`;
      await page.goto(url, { waitUntil: 'commit' });
      await page.waitForTimeout(400);
      const executed = await page.evaluate((m) => window.__wp4xss === m, marker);
      const domText = await page.evaluate(() => document.body ? document.body.innerText : '');
      const html = await page.content();
      await record(runIdFor(sample, level), {
        sample_id: sample,
        security_level: level,
        scenario: 'reflected',
        payload,
        url,
        marker,
        executed,
        marker_in_dom_text: domText.includes(marker),
        marker_in_raw_html: html.includes(payload),
        raw_svg_element_present: html.includes('<svg onload='),
      }, page, [...logs], [...errors]);
    }

    // XSS-004: impossible level, token required, output encoding.
    await setSecurity(page, 'impossible');
    const marker4 = 'WP4XSS004';
    const payload4 = payloadFor(marker4);
    await page.goto(`${BASE}/vulnerabilities/xss_r/`, { waitUntil: 'commit' });
    const token = await page.locator('input[name="user_token"]').first().getAttribute('value');
    const url4 = `${BASE}/vulnerabilities/xss_r/?name=${encodeURIComponent(payload4)}&user_token=${token}`;
    await page.goto(url4, { waitUntil: 'commit' });
    await page.waitForTimeout(400);
    const executed4 = await page.evaluate((m) => window.__wp4xss === m, marker4);
    const html4 = await page.content();
    const domText4 = await page.evaluate(() => document.body ? document.body.innerText : '');
    const encoded4 = html4.includes('&lt;svg') && !html4.includes('<svg onload=');
    const missingTokenUrl = `${BASE}/vulnerabilities/xss_r/?name=${encodeURIComponent(payload4)}`;
    await page.goto(missingTokenUrl, { waitUntil: 'commit' });
    await page.waitForTimeout(300);
    const missingTokenRedirected = page.url().includes('/index.php');
    await record(runIdFor('XSS-004', 'impossible'), {
      sample_id: 'XSS-004',
      security_level: 'impossible',
      scenario: 'encoded-output-with-token',
      payload: payload4,
      url: url4,
      marker: marker4,
      executed: executed4,
      marker_in_dom_text: domText4.includes(marker4),
      marker_in_raw_html: html4.includes(payload4),
      encoded_output_observed: encoded4,
      missing_token_redirected: missingTokenRedirected,
    }, page, [...logs], [...errors]);

    // XSS-005: stored low write then low read.
    await setSecurity(page, 'low');
    const marker5 = 'WP4XSS005';
    // The guestbook textarea enforces maxlength=50, so keep the stored payload short.
    const payload5 = `<svg onload="window.__wp4xss='${marker5}'">`;
    await page.goto(`${BASE}/vulnerabilities/xss_s/`, { waitUntil: 'commit' });
    await page.fill('input[name="txtName"]', 'wp4x5');
    await page.fill('textarea[name="mtxMessage"]', payload5);
    await page.click('input[name="btnSign"]');
    await page.waitForTimeout(1500);
    await page.goto(`${BASE}/vulnerabilities/xss_s/`, { waitUntil: 'commit' });
    await page.waitForTimeout(500);
    const executed5 = await page.evaluate((m) => window.__wp4xss === m, marker5);
    const html5 = await page.content();
    const domText5 = await page.evaluate(() => document.body ? document.body.innerText : '');
    await record(runIdFor('XSS-005', 'low'), {
      sample_id: 'XSS-005',
      security_level: 'low',
      scenario: 'stored-write-then-read',
      payload: payload5,
      marker: marker5,
      name: 'wp4x5',
      executed: executed5,
      marker_in_dom_text: domText5.includes(marker5),
      marker_in_raw_html: html5.includes(payload5),
    }, page, [...logs], [...errors]);
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});


