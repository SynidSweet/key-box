// The app shell (KBOX-8, KBOX-9, KBOX-11): a view session opens the queue; each approval, each denial and each signed
// operation asks for the passkey and the device key again over its own challenge. Box words are shown as text only.
import { approvalChallenge, browser, byId, call, denialChallenge, fromB64u, nonce, notifier, operationChallenge, post, prove, viewChallenge } from './webauthn-client.js';

/** @typedef {{ approval_id: string, kind: string, title: string, lines: string[], digest_b64: string, nonce_b64: string }} Item */

/** @param {unknown} v @returns {v is Item} */
function isItem(v) {
  if (typeof v !== 'object' || v === null) return false;
  const o = /** @type {Record<string, unknown>} */ (v);
  return ['approval_id', 'kind', 'title', 'digest_b64', 'nonce_b64'].every((k) => typeof o[k] === 'string') && Array.isArray(o['lines']) && o['lines'].every((l) => typeof l === 'string');
}

/** @param {Item} item @param {'approve' | 'deny'} decision */
async function decide(item, decision) {
  try {
    const n = fromB64u(item.nonce_b64);
    const challenge = decision === 'approve' ? approvalChallenge : denialChallenge;
    const proof = await prove(n, await challenge(item.approval_id, fromB64u(item.digest_b64), n));
    await call(`/app/${decision}/${item.approval_id}`, { proof });
    notifier.say(decision === 'approve' ? 'Approved.' : 'Denied.');
    await openQueue();
  } catch (error) {
    notifier.failed(error);
  }
}

/** @param {Item} item */
function card(item) {
  const doc = browser().document;
  const box = doc.createElement('div');
  box.className = 'card';
  const title = doc.createElement('h2');
  title.textContent = item.title;
  box.append(title);
  for (const line of item.lines) {
    const p = doc.createElement('p');
    p.textContent = line;
    box.append(p);
  }
  const approve = doc.createElement('button');
  approve.textContent = 'Approve';
  approve.addEventListener('click', () => void decide(item, 'approve'));
  const deny = doc.createElement('button');
  deny.textContent = 'Deny';
  deny.className = 'deny';
  deny.addEventListener('click', () => void decide(item, 'deny'));
  box.append(approve, deny);
  return box;
}

async function openQueue() {
  const answer = /** @type {{ phrase?: unknown, approvals?: unknown }} */ (await call('/app/queue'));
  const items = Array.isArray(answer.approvals) ? answer.approvals.filter(isItem) : [];
  const phrase = byId('phrase');
  phrase.textContent = typeof answer.phrase === 'string' ? `Your phrase: ${answer.phrase}` : '';
  phrase.hidden = typeof answer.phrase !== 'string';
  byId('queue').replaceChildren(...items.map(card));
  byId('tools').hidden = false;
  if (items.length === 0) notifier.say('Nothing waits.');
}

byId('open').addEventListener('click', () => {
  void (async () => {
    try {
      const n = await nonce('view');
      await call('/app/view', { proof: await prove(n, await viewChallenge(n)) });
      await openQueue();
    } catch (error) {
      notifier.failed(error);
    }
  })();
});

/** @param {'enrol_window_open' | 'token_revoke'} kind */
async function operation(kind) {
  try {
    const op = { kind, label: byId('label').value.trim() };
    const n = await nonce('op');
    await call('/app/op', { op, proof: await prove(n, await operationChallenge(op, n)) });
    notifier.say(kind === 'enrol_window_open' ? `${op.label} may enrol for ten minutes.` : `${op.label}'s pass is revoked.`);
  } catch (error) {
    notifier.failed(error);
  }
}

byId('window').addEventListener('click', () => void operation('enrol_window_open'));
byId('revoke').addEventListener('click', () => void operation('token_revoke'));
// Adding a phone (spec revision 4): this phone asks for a one-time code; the new phone registers with it and shows a
// fingerprint; the approval then appears in this queue with the same fingerprint beside "Compare with the new phone".
byId('add-phone').addEventListener('click', () => {
  void post('/app/propose-approver-add').then(
    (answer) => {
      const code = /** @type {{ registration_code?: unknown }} */ (answer).registration_code;
      if (typeof code !== 'string') throw new Error('the box sent no registration code');
      notifier.say(`On the new phone, open /recover and enter within 10 minutes: ${code}. Then approve here only if the words match the new phone.`);
    },
    (error) => notifier.failed(error),
  ).catch((error) => notifier.failed(error));
});
