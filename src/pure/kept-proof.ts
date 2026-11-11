// KBOX-6, KBOX-9: root's own check of a kept approval proof. kb-install never takes core's word that an approval happened: it
// rebuilds the action from the request, and checks the passkey assertion and the device-key signature of the SAME approver
// over the `kbox-v1` challenge, against the approvers and the domain of the root copy (trust.json), with the one verifier.
// Nonce use and the pending state stay core's checks.
import type { ApprovalProof, TrustApprover } from '../ports/trust.ts';
import { actionDigest, approvalChallenge, relyingParty, verifyProof } from './challenge.ts';
import { decodeCoseEs256, parseRawPoint } from './cose.ts';
import type { Es256PublicKey } from './cose.ts';

export interface TrustCopy {
  readonly domain: string;
  readonly approvers: readonly TrustApprover[];
}

const bytes = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'base64url'));

/** An approver's two public keys, or undefined when either does not decode. */
export function approverKeys(a: TrustApprover): { readonly passkey: Es256PublicKey; readonly device: Es256PublicKey } | undefined {
  const passkey = decodeCoseEs256(bytes(a.cose_b64));
  const device = parseRawPoint(bytes(a.device_pub_b64));
  return passkey.ok && device.ok ? { passkey: passkey.key, device: device.key } : undefined;
}

/** True only when an approver of the root copy signed exactly this action, with both keys, for the root copy's domain. */
export function keptProofHolds(trust: TrustCopy, proof: ApprovalProof, action: object): boolean {
  const signer = trust.approvers.find((a) => a.id === proof.approver_id);
  const keys = signer === undefined ? undefined : approverKeys(signer);
  if (keys === undefined) return false;
  const nonce = bytes(proof.nonce_b64);
  if (nonce.length !== 32) return false;
  const rp = relyingParty(trust.domain);
  const challenge = approvalChallenge(proof.approval_id, actionDigest(action), nonce);
  // The root copy keeps no credential id, so the proof's own id is the one compared: the check that binds the proof to the
  // approver is the passkey signature against the approver's COSE key, then the device key of that same approver.
  const credentialId = bytes(proof.credential_id_b64);
  const verdict = verifyProof(
    { approverId: proof.approver_id, credentialId, passkey: keys.passkey, device: keys.device },
    {
      credentialId,
      authenticatorData: bytes(proof.authenticator_data_b64),
      clientDataJSON: bytes(proof.client_data_json_b64),
      signature: bytes(proof.signature_b64),
      deviceSignature: bytes(proof.device_signature_b64),
    },
    { challenge, origin: rp.origin, rpId: rp.rpId, storedCounter: 0 },
  );
  return verdict.ok;
}
