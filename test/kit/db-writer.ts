// A helper process for the tests that need two real writers on one database file. Run with no arguments (as
// `node --test` does to every file under test/) it does nothing.
import { createAuditLog } from '../../src/shell/audit.ts';
import { openMetaDatabase } from '../../src/shell/db.ts';
import { seededRandom } from './random.ts';

const [mode, path, label, count] = process.argv.slice(2);

if (mode === 'audit' && path !== undefined && label !== undefined && count !== undefined) {
  const db = openMetaDatabase(path, seededRandom(1));
  const log = createAuditLog(db);
  for (let i = 0; i < Number(count); i += 1) log.append({ actor: label, action: 'api.request', subject: '/api/meta', at: i, detail: { request_id: 'req_AAAAAAAAAAAA', method: 'GET', status: 200 } });
  db.close();
}
