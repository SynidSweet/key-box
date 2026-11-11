// Registering this phone as an approver (KBOX-49, KBOX-20): the words, then a new passkey and device key proven over the
// registration challenge, with a push subscription when the phone offers one.
import { byId, call, nonce, notifier, pushSubscription, registerApprover } from './webauthn-client.js';

/**
 * Registers this phone at one of the box's registration routes. Every failure is shown on the page.
 * @param {'/setup' | '/recover' | '/recover/register'} path @param {string} button @param {string} done
 */
export async function register(path, button, done) {
  const go = byId(button);
  go.disabled = true;
  try {
    const code = byId('code').value.trim().toLowerCase().split(/\s+/).join(' ');
    const phrase = byId('phrase').value;
    notifier.say('Waiting for the passkey…');
    const { approver, proof } = await registerApprover(await nonce('register'));
    /** @type {{ endpoint: string, p256dh: string, auth: string } | undefined} */
    let subscription;
    try {
      subscription = await pushSubscription();
    } catch (error) {
      notifier.say(`Notifications are off on this phone (${error instanceof Error ? error.message : 'refused'}); open the app to see what waits.`);
    }
    const answer = await call(path, { code, approver, proof, phrase, ...(subscription === undefined ? {} : { subscription }) });
    // Adding a phone (spec revision 4): the box holds this phone as pending and names it by a fingerprint the approving phone shows too.
    const fingerprint = typeof answer === 'object' && answer !== null && 'fingerprint' in answer && typeof answer.fingerprint === 'string' ? answer.fingerprint : undefined;
    notifier.say(fingerprint === undefined ? done : `${done} Fingerprint: ${fingerprint}`);
  } catch (error) {
    notifier.failed(error);
  } finally {
    go.disabled = false;
  }
}
