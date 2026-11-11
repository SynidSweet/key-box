// A throwaway self-signed certificate for a local TLS server, made by the openssl command in a temp directory that is
// removed when the test ends. A missing openssl fails the test; it never skips.
import type { TestContext } from 'node:test';
import { makeCertificate } from './cert.ts';
import type { TestCertificate } from './cert.ts';
import { tempDir } from './temp.ts';

export type { TestCertificate };

export async function selfSignedCertificate(t: TestContext, name: string): Promise<TestCertificate> {
  return makeCertificate(await tempDir(t), name);
}
