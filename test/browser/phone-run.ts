// The owner's phone, in a real Chromium: a 390 x 844 touch viewport at scale 3 with a CDP virtual passkey authenticator, walking the box's phone
// pages against the demo (test/support/demo-pages.ts): setup with the setup code, the queue, an approval, a denial, the pending phone's approval,
// the paste page (a refused value, then a good one) and recovery. A PNG per state goes to the output directory; every console error, page error and
// failed or refused request is printed at the end. It needs Chromium, so it is no test file: the gate does not collect it.
// Run `node test/browser/phone-run.ts <output dir>`; it exits non-zero when a step fails. Under `node --test` this file does nothing.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEMO_PASTE_VALUE, startDemo } from '../support/demo-pages.ts';
import type { Demo } from '../support/demo-pages.ts';
import { launchChromium } from './cdp.ts';
import type { Cdp, CdpEvent } from './cdp.ts';

const VIEWPORT = { width: 390, height: 844 } as const;
const MOBILE_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36';
const STEP_MS = 20_000;

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;
const nap = (ms: number): Promise<void> => new Promise((resolve) => void setTimeout(resolve, ms));

/** What the browser said that a person would call wrong. */
interface Trouble {
  readonly kind: 'console error' | 'page error' | 'request failed' | 'request refused';
  readonly text: string;
}

class Phone {
  readonly trouble: Trouble[] = [];
  readonly shots: { readonly file: string; readonly state: string; readonly overflowPx: number }[] = [];
  readonly #cdp: Cdp;
  readonly #session: string;
  readonly #out: string;
  readonly #urls = new Map<string, string>();
  readonly #refused = new Set<string>();

  private constructor(cdp: Cdp, session: string, out: string) {
    this.#cdp = cdp;
    this.#session = session;
    this.#out = out;
    cdp.on((event) => this.#watch(event));
  }

  static async open(cdp: Cdp, out: string): Promise<Phone> {
    const created = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const attached = await cdp.send('Target.attachToTarget', { targetId: isRecord(created) ? created['targetId'] : '', flatten: true });
    const session = isRecord(attached) && typeof attached['sessionId'] === 'string' ? attached['sessionId'] : '';
    const phone = new Phone(cdp, session, out);
    for (const domain of ['Page', 'Runtime', 'Log', 'Network', 'WebAuthn']) await phone.send(`${domain}.enable`);
    await phone.send('Emulation.setDeviceMetricsOverride', { ...VIEWPORT, deviceScaleFactor: 3, mobile: true });
    await phone.send('Emulation.setTouchEmulationEnabled', { enabled: true, maxTouchPoints: 5 });
    await phone.send('Emulation.setUserAgentOverride', { userAgent: MOBILE_UA });
    await phone.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });
    return phone;
  }

  send(method: string, params: object = {}): Promise<unknown> {
    return this.#cdp.send(method, params, this.#session);
  }

  #watch(event: CdpEvent): void {
    if (event.sessionId !== this.#session || !isRecord(event.params)) return;
    const p = event.params;
    switch (event.method) {
      case 'Runtime.consoleAPICalled':
        if (p['type'] === 'error') this.trouble.push({ kind: 'console error', text: JSON.stringify(p['args']) });
        break;
      case 'Runtime.exceptionThrown':
        this.trouble.push({ kind: 'page error', text: JSON.stringify(p['exceptionDetails']) });
        break;
      case 'Log.entryAdded':
        if (isRecord(p['entry']) && p['entry']['level'] === 'error') this.trouble.push({ kind: 'console error', text: `${String(p['entry']['text'])} ${String(p['entry']['url'] ?? '')}` });
        break;
      case 'Network.requestWillBeSent':
        if (typeof p['requestId'] === 'string' && isRecord(p['request'])) this.#urls.set(p['requestId'], String(p['request']['url']));
        break;
      case 'Network.loadingFailed':
        this.trouble.push({ kind: 'request failed', text: `${this.#urls.get(String(p['requestId'])) ?? '?'} ${String(p['errorText'])}` });
        break;
      case 'Network.responseReceived':
        if (isRecord(p['response']) && typeof p['response']['status'] === 'number' && p['response']['status'] >= 400) {
          this.trouble.push({ kind: 'request refused', text: `${p['response']['status']} ${String(p['response']['url'])}` });
          this.#refused.add(String(p['requestId']));
        }
        break;
      case 'Network.loadingFinished':
        if (this.#refused.delete(String(p['requestId']))) void this.#noteBody(String(p['requestId']));
        break;
      default:
        break;
    }
  }

  /** What the box said when it refused a request, kept beside the refusal. */
  async #noteBody(requestId: string): Promise<void> {
    const answer = await this.send('Network.getResponseBody', { requestId }).catch((error: unknown) => ({ body: `no body: ${String(error)}` }));
    this.trouble.push({ kind: 'request refused', text: `  its answer: ${isRecord(answer) ? String(answer['body']) : ''}` });
  }

  /** Evaluates an expression in the page and returns its JSON value; an exception in the page is thrown here. */
  async eval(expression: string): Promise<unknown> {
    const answer = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (isRecord(answer) && isRecord(answer['exceptionDetails'])) throw new Error(`in the page: ${JSON.stringify(answer['exceptionDetails'])}`);
    return isRecord(answer) && isRecord(answer['result']) ? answer['result']['value'] : undefined;
  }

  async goto(url: string): Promise<void> {
    const loaded = this.#once('Page.loadEventFired');
    await this.send('Page.navigate', { url });
    await loaded;
    // A fragment-only change fires no load event: the caller waits for what it needs on the page.
  }

  #once(method: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no ${method} in ${STEP_MS} ms`)), STEP_MS);
      this.#cdp.on((event) => {
        if (event.method === method && event.sessionId === this.#session) {
          clearTimeout(timer);
          resolve();
        }
      });
    });
  }

  async waitFor(condition: string, what: string): Promise<void> {
    for (let waited = 0; waited < STEP_MS; waited += 100) {
      if ((await this.eval(`Boolean(${condition})`)) === true) return;
      await nap(100);
    }
    throw new Error(`timed out waiting for ${what}; the page says: ${JSON.stringify(await this.eval('document.body.innerText'))}`);
  }

  text(selector: string): Promise<unknown> {
    return this.eval(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? null`);
  }

  /** A touch tap at the middle of the element the expression finds (scrolled into view first). */
  async tapAt(element: string): Promise<void> {
    const point = await this.eval(`(() => { const e = ${element}; if (!e) return null; e.scrollIntoView({ block: 'center' }); const r = e.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2 }; })()`);
    if (!isRecord(point) || typeof point['x'] !== 'number' || typeof point['y'] !== 'number') throw new Error(`nothing to tap: ${element}`);
    const touchPoints = [{ x: point['x'], y: point['y'] }];
    await this.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints });
    await this.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
  }

  tap(selector: string): Promise<void> {
    return this.tapAt(`document.querySelector(${JSON.stringify(selector)})`);
  }

  /** The button called `label` on the card whose heading contains `heading`. */
  tapCardButton(heading: string, label: string): Promise<void> {
    const card = `[...document.querySelectorAll('#queue .card')].find((c) => c.querySelector('h2')?.textContent.includes(${JSON.stringify(heading)}))`;
    return this.tapAt(`[...(${card})?.querySelectorAll('button') ?? []].find((b) => b.textContent === ${JSON.stringify(label)})`);
  }

  /** Types into a field the way a keyboard would. */
  async fill(selector: string, value: string): Promise<void> {
    await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); e.scrollIntoView({ block: 'center' }); e.focus(); e.select?.(); })()`);
    await this.send('Input.insertText', { text: value });
  }

  /** A PNG of the whole page as it is now, and a note of any sideways overflow beyond the 390 px of the phone. */
  async shot(state: string): Promise<void> {
    const metrics = await this.send('Page.getLayoutMetrics');
    const size = isRecord(metrics) && isRecord(metrics['cssContentSize']) ? metrics['cssContentSize'] : {};
    const height = typeof size['height'] === 'number' ? Math.ceil(size['height']) : VIEWPORT.height;
    const taken = await this.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: VIEWPORT.width, height, scale: 1 } });
    const data = isRecord(taken) && typeof taken['data'] === 'string' ? taken['data'] : '';
    const file = `${String(this.shots.length + 1).padStart(2, '0')}-${state}.png`;
    writeFileSync(join(this.#out, file), Buffer.from(data, 'base64'));
    const wide = await this.eval('document.documentElement.scrollWidth');
    this.shots.push({ file, state, overflowPx: typeof wide === 'number' ? Math.max(0, wide - VIEWPORT.width) : -1 });
  }
}

/** The text a status line settles on once `done` holds, whether the page succeeded or said why not. */
async function settled(phone: Phone, done: string, what: string): Promise<string> {
  await phone.waitFor(`${done} || /fail|refus|error|could not|cannot|not |unavailable/i.test(document.querySelector('#status')?.textContent ?? '')`, what);
  return String(await phone.text('#status'));
}

async function walk(phone: Phone, demo: Demo, notes: string[]): Promise<void> {
  const url = (name: string): string => demo.pages.find((p) => p.name.includes(name))?.url ?? '';
  const ok = (what: string, status: string): void => void notes.push(`${what}: ${status}`);

  // Setup: the twelve words from the console, a phrase, a passkey and a device key.
  await phone.goto(url('setup'));
  await phone.shot('setup-empty');
  await phone.fill('#code', demo.setupCode);
  await phone.fill('#phrase', 'blue kettle');
  await phone.shot('setup-filled');
  await phone.tap('#go');
  ok('setup', await settled(phone, "document.querySelector('#status').textContent.includes('approves for the box')", 'the setup answer'));
  await phone.shot('setup-done');

  // The app: a view session (passkey and device key), then the queue.
  await phone.goto(url('the app'));
  await phone.shot('app-start');
  await phone.tap('#open');
  await phone.waitFor("document.querySelectorAll('#queue .card').length > 0", 'the queue');
  await phone.shot('queue');
  await demo.pendingPhone;
  await phone.tap('#open');
  await phone.waitFor("[...document.querySelectorAll('#queue h2')].some((h) => /approver/i.test(h.textContent))", 'the pending phone approval');
  await phone.shot('queue-with-pending-phone');

  // Approve the rotation, deny the update, approve the new phone.
  const listed = await phone.eval("[...document.querySelectorAll('#queue h2')].map((h) => h.textContent)");
  const titles = Array.isArray(listed) ? listed.map(String) : [];
  notes.push(`queue titles: ${JSON.stringify(titles)}`);
  const titleOf = (re: RegExp): string => titles.find((t) => re.test(t)) ?? '';
  const rotation = titleOf(/rotat/i);
  const update = titleOf(/updat|install/i);
  const phoneAdd = titleOf(/approver/i);
  await phone.tapCardButton(rotation, 'Approve');
  ok('approve rotation', await settled(phone, "document.querySelector('#status').textContent === 'Approved.'", 'the approval'));
  await phone.shot('after-approve-rotation');
  await phone.tapCardButton(update, 'Deny');
  ok('deny update', await settled(phone, "document.querySelector('#status').textContent === 'Denied.'", 'the denial'));
  await phone.shot('after-deny-update');
  await phone.tapCardButton(phoneAdd, 'Approve');
  ok('approve new phone (last card: the page then says Nothing waits)', await settled(phone, "['Approved.', 'Nothing waits.'].includes(document.querySelector('#status').textContent)", 'the new phone approval'));
  await phone.shot('after-approve-new-phone');

  // The tools: a machine may enrol for ten minutes; another phone's registration code.
  await phone.tap('#add-phone');
  await phone.waitFor("document.querySelector('#status').textContent.includes('registration') || document.querySelector('#status').textContent.includes('On the new phone')", 'the registration code');
  await phone.shot('add-another-phone-code');
  await phone.fill('#label', 'ws-1');
  await phone.tap('#window');
  ok('enrol window', await settled(phone, "document.querySelector('#status').textContent.includes('may enrol')", 'the enrol window'));
  await phone.shot('enrol-window');

  // The paste page: a value that is too short is refused and kept; the right one is stored.
  await phone.goto(url('paste'));
  await phone.waitFor("document.querySelector('#phrase').textContent.includes('Your phrase')", 'the paste task');
  await phone.shot('paste-task');
  await phone.fill('#value', 'pk-short');
  await phone.tap('#send');
  ok('paste, too short', await settled(phone, 'false', 'the refusal of a short value'));
  await phone.shot('paste-refused');
  await phone.eval("document.querySelector('#status').textContent = ''");
  await phone.fill('#value', DEMO_PASTE_VALUE);
  await phone.tap('#send');
  ok('paste, good value', await settled(phone, "document.querySelector('#status').textContent.includes('Stored')", 'the paste answer'));
  await phone.shot('paste-stored');

  // Recovery: as far as one phone goes, which is the console's words.
  await phone.goto(url('recovery'));
  await phone.shot('recover-empty');
  await phone.fill('#code', demo.recoveryCode);
  await phone.fill('#phrase', 'red lantern');
  await phone.shot('recover-filled');
  await phone.tap('#recover');
  ok('recover', await settled(phone, "document.querySelector('#status').textContent.includes('only approver')", 'the recovery answer'));
  await phone.shot('recover-done');
}

async function main(out: string): Promise<void> {
  mkdirSync(out, { recursive: true });
  const demo = await startDemo();
  const notes: string[] = [];
  // The seeding of the pending phone fails on its own clock: it is reported with the notes, and awaited again where the walk needs it.
  void demo.pendingPhone.then(
    () => undefined,
    (error: unknown) => void notes.push(`the pending phone was not seeded: ${error instanceof Error ? error.message : String(error)}`),
  );
  let browser: Awaited<ReturnType<typeof launchChromium>> | undefined;
  let phone: Phone | undefined;
  try {
    browser = await launchChromium('keys.localhost', demo.port);
    phone = await Phone.open(browser.cdp, out);
    await walk(phone, demo, notes);
  } catch (error) {
    if (phone !== undefined) {
      await phone.shot('where-it-stopped').catch((shotError: unknown) => {
        throw new AggregateError([error, shotError], 'the run stopped, and the screenshot of where it stopped failed');
      });
    }
    throw error;
  } finally {
    browser?.cdp.close();
    await browser?.stop();
    await demo.stop();
    for (const s of phone?.shots ?? []) process.stdout.write(`shot\t${s.file}\toverflow ${s.overflowPx}px\n`);
    for (const n of notes) process.stdout.write(`note\t${n}\n`);
    for (const t of phone?.trouble ?? []) process.stdout.write(`trouble\t${t.kind}\t${t.text}\n`);
  }
}

const out = process.argv[2];
if (import.meta.main && !process.env['NODE_TEST_CONTEXT'] && out !== undefined) await main(out);
