// A throwaway self-signed certificate made by the openssl command inside a directory the caller owns and removes. A missing
// openssl throws; nothing skips.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export interface TestCertificate {
  readonly key: string;
  readonly cert: string;
}

export function makeCertificate(dir: string, name: string): TestCertificate {
  const key = join(dir, 'key.pem');
  const cert = join(dir, 'cert.pem');
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', `/CN=${name}`, '-addext', `subjectAltName=DNS:${name}`], { encoding: 'utf8', timeout: 20_000 });
  if (made.error !== undefined) throw made.error;
  if (made.status !== 0) throw new Error(`openssl could not make a test certificate: ${made.stderr}`);
  return { key: readFileSync(key, 'utf8'), cert: readFileSync(cert, 'utf8') };
}
