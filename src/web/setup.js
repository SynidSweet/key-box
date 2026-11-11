// The setup page (KBOX-49): the twelve words from the box's console, then the first approver.
import { register } from './register.js';
import { byId } from './webauthn-client.js';

byId('go').addEventListener('click', () => void register('/setup', 'go', 'This phone approves for the box now.'));
