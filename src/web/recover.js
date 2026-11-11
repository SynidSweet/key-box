// The recovery page (KBOX-20): the console's words make this phone the only approver; another phone's words add it.
import { register } from './register.js';
import { byId } from './webauthn-client.js';

byId('recover').addEventListener('click', () => void register('/recover', 'recover', 'This phone is now the only approver.'));
byId('add').addEventListener('click', () => void register('/recover/register', 'add', 'This phone waits for an approver to approve it: they must see the same words.'));
