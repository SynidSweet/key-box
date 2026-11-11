// A helper process for the tests that need a second real writer on one database file. Run with no arguments (as
// `node --test` does to every file under test/) it does nothing.
import { createAuditLog } from '../../src/shell/audit.ts';
import { systemClock } from '../../src/shell/clock.ts';
import { openMetaDatabase } from '../../src/shell/db.ts';
import { createEventHub } from '../../src/shell/events.ts';
import { createMetaStore } from '../../src/shell/meta.ts';
import { seededRandom } from './random.ts';

const [mode, path, label, count] = process.argv.slice(2);

if (path !== undefined && label !== undefined && count !== undefined) {
  const db = openMetaDatabase(path, seededRandom(1));
  if (mode === 'audit') {
    const log = createAuditLog(db);
    for (let i = 0; i < Number(count); i += 1) log.append({ actor: label, action: 'api.request', subject: '/api/meta', at: i, detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200 } });
  } else if (mode === 'meta') {
    // `label` is the key reference: write generation 1, 2, ... so that the key's generation always equals the event count.
    const store = createMetaStore(db, systemClock, createEventHub());
    for (let i = 1; i <= Number(count); i += 1) {
      store.putKey({ keyref: label, platform: 'openai', name: 'OPENAI_ADMIN_KEY', projects: [], class: 'admin', status: 'works', gen_current: i, schedule: { rotate_every_days: 30, grace_hours: 24, next_due_at: null, expires_at: null }, coverage: null, last_use_at: null });
    }
  }
  db.close();
}
