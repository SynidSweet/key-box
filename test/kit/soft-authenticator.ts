// A software passkey plus device key. It builds authenticator data, COSE keys and signatures itself and
// imports nothing from src/pure/{webauthn,cose,challenge}.ts, so verifier and authenticator cannot share
// a mistake (KBOX-35; checked by test/arch.test.ts).
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import type { JsonWebKey, KeyObject } from 'node:crypto';
import { cborEncode } from './cbor.ts';

export interface SoftCredential {
  readonly credentialId: Uint8Array;
  readonly coseKey: Uint8Array;
  readonly publicJwk: JsonWebKey;
}

export interface SoftAssertion {
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Buffer;
  readonly clientDataJSON: Buffer;
  /** DER-encoded ECDSA P-256 over authenticatorData || sha256(clientDataJSON). */
  readonly signature: Buffer;
}

export interface AssertRequest {
  readonly rpId: string;
  readonly origin: string;
  readonly challenge: Uint8Array;
}

export interface SoftAuthenticator {
  createCredential(): SoftCredential;
  assert(req: AssertRequest): SoftAssertion;
  /** DER-encoded ECDSA P-256 over the payload with the device key. */
  deviceSign(payload: Uint8Array): Buffer;
  readonly devicePublicJwk: JsonWebKey;
}

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;

function coseEs256(jwk: JsonWebKey): Uint8Array {
  const x = Buffer.from(jwk.x ?? '', 'base64url');
  const y = Buffer.from(jwk.y ?? '', 'base64url');
  return cborEncode(
    new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]),
  );
}

export function softAuthenticator(): SoftAuthenticator {
  const device = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  let passkey: { privateKey: KeyObject; credential: SoftCredential } | undefined;
  let counter = 0;

  const current = (): { privateKey: KeyObject; credential: SoftCredential } => {
    if (passkey === undefined) {
      const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const publicJwk = pair.publicKey.export({ format: 'jwk' });
      passkey = { privateKey: pair.privateKey, credential: { credentialId: randomBytes(16), coseKey: coseEs256(publicJwk), publicJwk } };
    }
    return passkey;
  };
  const createCredential = (): SoftCredential => current().credential;

  const assert = (req: AssertRequest): SoftAssertion => {
    const { privateKey, credential } = current();
    counter += 1;
    const authenticatorData = Buffer.alloc(37);
    createHash('sha256').update(req.rpId).digest().copy(authenticatorData, 0);
    authenticatorData[32] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
    authenticatorData.writeUInt32BE(counter, 33);
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: Buffer.from(req.challenge).toString('base64url'), origin: req.origin }),
    );
    const signed = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]);
    const signature = sign('sha256', signed, { key: privateKey, dsaEncoding: 'der' });
    return { credentialId: credential.credentialId, authenticatorData, clientDataJSON, signature };
  };

  return {
    createCredential,
    assert,
    deviceSign: (payload) => sign('sha256', payload, { key: device.privateKey, dsaEncoding: 'der' }),
    devicePublicJwk: device.publicKey.export({ format: 'jwk' }),
  };
}
