// Throwaway system users for a root-only test: made when missing, and only the ones made here are removed afterwards.
import { spawnSync } from 'node:child_process';

export interface SystemUser {
  readonly name: string;
  readonly uid: number;
  /** The user's own primary group, made with it. */
  readonly gid: number;
}

export interface SystemUsers {
  readonly users: Readonly<Record<string, SystemUser>>;
  /** Names of the users this call made, not those that were already there. */
  readonly made: readonly string[];
  /** Deletes the users this call made. Throws if a delete fails. */
  remove(): void;
}

function run(command: string, args: readonly string[]): { status: number | null; stdout: string } {
  const result = spawnSync(command, [...args], { encoding: 'utf8' });
  if (result.error !== undefined) throw new Error(`cannot run ${command}: ${result.error.message}`);
  return { status: result.status, stdout: result.stdout };
}

function lookup(name: string): SystemUser | undefined {
  const uid = run('id', ['-u', name]);
  if (uid.status !== 0) return undefined;
  return { name, uid: Number(uid.stdout.trim()), gid: Number(run('id', ['-g', name]).stdout.trim()) };
}

/** Needs root. Creates each missing user with `useradd --system` and no login shell; a missing `useradd` or a failed create throws. */
export function ensureSystemUsers(names: readonly string[]): SystemUsers {
  if (process.getuid?.() !== 0) throw new Error('making system users needs root: run this test through loop/gate.sh');
  const made: string[] = [];
  const users: Record<string, SystemUser> = {};
  const removeMade = (): void => {
    for (const name of made.splice(0)) if (run('userdel', [name]).status !== 0) throw new Error(`could not delete the user ${name} this test made`);
  };
  for (const name of names) {
    let user = lookup(name);
    if (user === undefined) {
      const created = run('useradd', ['--system', '--no-create-home', '--shell', '/usr/sbin/nologin', name]);
      if (created.status !== 0) {
        removeMade();
        throw new Error(`useradd ${name} failed with status ${created.status}`);
      }
      made.push(name);
      user = lookup(name);
    }
    if (user === undefined) {
      removeMade();
      throw new Error(`the user ${name} is not there after useradd`);
    }
    users[name] = user;
  }
  return { users, made: [...made], remove: removeMade };
}
