// A software approver: a passkey plus a device key registered together (KBOX-9). Like softAuthenticator() it builds
// authenticator data, COSE keys and signatures itself and imports nothing from src/pure/{webauthn,cose,challenge}.ts.
// Two things softAuthenticator() cannot do, which is why this file exists beside it: the device key signs raw r||s (as
// WebCrypto does), and an assertion can carry one planted fault (a quirk) under a VALID signature, so a refusal in a test
// is the check under test and never just a broken signature.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { JsonWebKey } from 'node:crypto';
import { cborEncode } from './cbor.ts';

export interface RelyingParty {
  readonly rpId: string;
  readonly origin: string;
}

/** One planted fault; every other field stays correct and the passkey signature is valid over what is sent. */
export interface Quirks {
  /** The flags byte; the default is UP | UV (0x05). */
  readonly flags?: number;
  readonly type?: string;
  readonly origin?: string;
  /** The rpId whose SHA-256 goes into authenticator data. */
  readonly rpIdHashOf?: string;
  readonly crossOrigin?: boolean;
  readonly topOrigin?: string;
  /** The signature counter; the default counts up from 1. */
  readonly counter?: number;
  /** Authenticator data with these bytes appended. */
  readonly trailing?: Uint8Array;
}

export interface ProofParts {
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  /** DER ECDSA P-256 over authenticatorData || SHA-256(clientDataJSON), as WebAuthn gives it. */
  readonly signature: Uint8Array;
  /** Raw 64-byte r||s ECDSA P-256 with SHA-256 over the challenge bytes, as WebCrypto gives it. */
  readonly deviceSignature: Uint8Array;
}

export interface SoftApprover {
  readonly credentialId: Uint8Array;
  /** The passkey's COSE_Key (EC2, P-256, ES256). */
  readonly coseKey: Uint8Array;
  /** The device key as an uncompressed P-256 point (0x04 || x || y), as WebCrypto exports it raw. */
  readonly devicePublicKey: Uint8Array;
  /** Passkey assertion and device-key signature over the same challenge. */
  prove(challenge: Uint8Array, rp: RelyingParty, quirks?: Quirks): ProofParts;
  /** Only the device-key signature over a payload. */
  deviceSign(payload: Uint8Array): Uint8Array;
}

const UP = 0x01;
const UV = 0x04;

const coord = (jwk: JsonWebKey, name: 'x' | 'y'): Buffer => Buffer.from(jwk[name] ?? '', 'base64url');

export function softApprover(): SoftApprover {
  const passkey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const device = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pj = passkey.publicKey.export({ format: 'jwk' });
  const dj = device.publicKey.export({ format: 'jwk' });
  const credentialId = Uint8Array.from(randomBytes(16));
  const coseKey = cborEncode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, coord(pj, 'x')],
      [-3, coord(pj, 'y')],
    ]),
  );
  const devicePublicKey = Uint8Array.from(Buffer.concat([Buffer.from([4]), coord(dj, 'x'), coord(dj, 'y')]));
  let counter = 0;
  const deviceSign = (payload: Uint8Array): Uint8Array => Uint8Array.from(sign('sha256', payload, { key: device.privateKey, dsaEncoding: 'ieee-p1363' }));

  const prove = (challenge: Uint8Array, rp: RelyingParty, q: Quirks = {}): ProofParts => {
    counter += 1;
    const head = Buffer.alloc(37);
    createHash('sha256').update(q.rpIdHashOf ?? rp.rpId).digest().copy(head, 0);
    head[32] = q.flags ?? UP | UV;
    head.writeUInt32BE(q.counter ?? counter, 33);
    const authenticatorData = Buffer.concat([head, Buffer.from(q.trailing ?? new Uint8Array())]);
    const client: Record<string, unknown> = { type: q.type ?? 'webauthn.get', challenge: Buffer.from(challenge).toString('base64url'), origin: q.origin ?? rp.origin };
    if (q.crossOrigin !== undefined) client['crossOrigin'] = q.crossOrigin;
    if (q.topOrigin !== undefined) client['topOrigin'] = q.topOrigin;
    const clientDataJSON = Buffer.from(JSON.stringify(client));
    const signed = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]);
    return {
      credentialId,
      authenticatorData: Uint8Array.from(authenticatorData),
      clientDataJSON: Uint8Array.from(clientDataJSON),
      signature: Uint8Array.from(sign('sha256', signed, { key: passkey.privateKey, dsaEncoding: 'der' })),
      deviceSignature: deviceSign(challenge),
    };
  };
  return { credentialId, coseKey, devicePublicKey, prove, deviceSign };
}
