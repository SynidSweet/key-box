// KBOX-56: schema versions. `PRAGMA user_version` is the version of one file; release 1's schema is version 0 (the version-0 statements are
// never edited). A list holds one entry per version step: entry `i` brings the file from version `i` to `i + 1`, as the statements it
// holds, run in order. Migrations are additive only (a new table, a new nullable column or a new index): a failed update runs the
// previous release over the same files (KBOX-6), so the release before must keep working on a newer file. The arch check refuses the rest.
import type { DatabaseSync } from 'node:sqlite';

export type Migration = readonly string[];

/** meta.db (kernel, rotation and paste tables). */
export const META_MIGRATIONS: readonly Migration[] = [
  // 1: the read call a key's verification makes (KBOX-40).
  ['ALTER TABLE rotation_keys ADD COLUMN verify_hint TEXT'],
  // 2: when an STS exchange signed with the generation first succeeded (KBOX-55: a box key is due only once proven).
  ['ALTER TABLE rotation_gens ADD COLUMN proved_at INTEGER'],
];

/** The private database's. */
export const PRIVATE_MIGRATIONS: readonly Migration[] = [];

const versionOf = (db: DatabaseSync): number => (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version;

/**
 * Brings the file to the newest version. Each pending migration runs in one `BEGIN IMMEDIATE` that re-reads the version first, so a second
 * process opening the file at once waits, finds it done and skips it. A migration that throws leaves the file at its old version
 * (`schema_migration_failed`, reported to `journal` and thrown). A file above the newest version is left as it is (`schema_newer`).
 */
export function migrate(db: DatabaseSync, migrations: readonly Migration[], journal: (code: string) => void): void {
  const start = versionOf(db);
  if (start > migrations.length) {
    journal('schema_newer');
    return;
  }
  for (const [offset, statements] of migrations.slice(start).entries()) {
    const from = start + offset;
    db.exec('BEGIN IMMEDIATE');
    try {
      if (versionOf(db) === from) {
        for (const statement of statements) db.exec(statement);
        db.exec(`PRAGMA user_version = ${from + 1}`);
      }
      db.exec('COMMIT');
    } catch (cause) {
      db.exec('ROLLBACK');
      journal('schema_migration_failed');
      throw new Error('schema_migration_failed', { cause });
    }
  }
}
