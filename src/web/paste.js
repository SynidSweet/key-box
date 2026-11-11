// The paste page (KBOX-12): the task's words, the owner's phrase, and a masked field. The paste goes with a passkey assertion and a device-key
// signature over the paste challenge, which binds the action as the box stored it. A refusal keeps the field so the owner can retry; the field
// is emptied only after the box stored the key.
import { browser, byId, call, fromB64u, notifier, pasteChallenge, prove } from './webauthn-client.js';

/** @typedef {{ paste_id: string, title: string, lines: string[], phrase: string, platform_link?: string, digest_b64: string, nonce_b64: string }} Task */

/** @param {unknown} v @returns {v is Task} */
function isTask(v) {
  if (typeof v !== 'object' || v === null) return false;
  const o = /** @type {Record<string, unknown>} */ (v);
  return ['paste_id', 'title', 'phrase', 'digest_b64', 'nonce_b64'].every((k) => typeof o[k] === 'string') && Array.isArray(o['lines']) && o['lines'].every((l) => typeof l === 'string');
}

/** The id of the task this page is for: the fragment of its address. */
const pasteId = () => browser().location.hash.slice(1);

/** @returns {Promise<Task>} */
async function load() {
  const task = await call(`/p/${pasteId()}`);
  if (!isTask(task)) throw new Error('the box sent a task this page does not understand');
  return task;
}

/** @param {Task} task */
function show(task) {
  const doc = browser().document;
  byId('phrase').textContent = `Your phrase: ${task.phrase}`;
  const lines = [task.title, ...task.lines].map((line) => {
    const p = doc.createElement('p');
    p.textContent = line;
    return p;
  });
  if (typeof task.platform_link === 'string') {
    const a = doc.createElement('a');
    a.textContent = 'The platform’s page for making a key';
    a.setAttribute('href', task.platform_link);
    a.setAttribute('rel', 'noreferrer');
    lines.push(a);
  }
  byId('words').replaceChildren(...lines);
}

byId('send').addEventListener('click', () => {
  void (async () => {
    try {
      // A fresh render each time: the box spends a nonce on every attempt, so a retry needs a new one.
      const task = await load();
      show(task);
      const n = fromB64u(task.nonce_b64);
      const proof = await prove(n, await pasteChallenge(task.paste_id, fromB64u(task.digest_b64), n));
      await call(`/p/${task.paste_id}`, { value: byId('value').value, proof });
      byId('value').value = '';
      notifier.say('Stored. The key is in the box.');
    } catch (error) {
      notifier.failed(error);
    }
  })();
});

void load().then(show, (error) => notifier.failed(error));
