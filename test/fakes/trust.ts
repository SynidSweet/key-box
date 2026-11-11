// The fake TrustPort: an in-memory trust.json with root's real checks. Setup and recovery codes are checked by the real root
// code store (src/shell/console.ts) and consumed on use; approver_add and approver_remove proofs are verified again against
// the copy as it stands, with the one verifier, as kb-install does (KBOX-6). A test can make root refuse the next request.
import type { TrustApprover, TrustPort, TrustRequest, TrustResult } from '../../src/ports/trust.ts';
import { actionDigest, approvalChallenge, relyingParty, verifyProof } from '../../src/pure/challenge.ts';
import { decodeCoseEs256, parseRawPoint } from '../../src/pure/cose.ts';
import type { CodeRoot } from '../../src/shell/console.ts';

export interface TrustCopy {
  readonly domain: string;
  readonly approvers: readonly TrustApprover[];
}

const bytes = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, 'base64url'));

export class FakeTrust implements TrustPort {
  readonly calls: TrustRequest[] = [];
  copy: TrustCopy | undefined;
  #refuseNext: string | undefined;
  readonly #codes: CodeRoot;
  readonly #bootId: () => string;
  /** Called with each request before root answers, so a test can see core's table at that moment. */
  onApply: (request: TrustRequest) => void = () => undefined;

  constructor(codes: CodeRoot, bootId: () => string) {
    this.#codes = codes;
    this.#bootId = bootId;
  }

  refuseNext(code: string): void {
    this.#refuseNext = code;
  }

  apply(request: TrustRequest): Promise<TrustResult> {
    this.calls.push(request);
    this.onApply(request);
    if (this.#refuseNext !== undefined) {
      const code = this.#refuseNext;
      this.#refuseNext = undefined;
      return Promise.resolve({ result: 'refused', code });
    }
    return Promise.resolve(this.#decide(request));
  }

  #decide(request: TrustRequest): TrustResult {
    const refused = (code: string): TrustResult => ({ result: 'refused', code });
    switch (request.change) {
      case 'setup': {
        const verdict = this.#codes.check('setup', request.code, { bootId: this.#bootId(), trustExists: this.copy !== undefined });
        if (!verdict.ok) return refused(verdict.code);
        this.#codes.consume('setup');
        this.copy = { domain: request.domain, approvers: request.approvers };
        return { result: 'applied' };
      }
      case 'recovery': {
        const verdict = this.#codes.check('recovery', request.code, { bootId: this.#bootId(), trustExists: this.copy !== undefined });
        if (!verdict.ok || this.copy === undefined) return refused(verdict.ok ? 'no_trust' : verdict.code);
        this.#codes.consume('recovery');
        this.copy = { domain: this.copy.domain, approvers: request.approvers };
        return { result: 'applied' };
      }
      case 'approver_add':
      case 'approver_remove': {
        if (this.copy === undefined) return refused('no_trust');
        const action = request.change === 'approver_add' ? { kind: 'approver_add' } : { kind: 'approver_remove', approver_id: request.approver_id };
        const p = request.approval;
        const signer = this.copy.approvers.find((a) => a.id === p.approver_id);
        const passkey = signer === undefined ? undefined : decodeCoseEs256(bytes(signer.cose_b64));
        const device = signer === undefined ? undefined : parseRawPoint(bytes(signer.device_pub_b64));
        if (passkey?.ok !== true || device?.ok !== true) return refused('bad_proof');
        const rp = relyingParty(this.copy.domain);
        const challenge = approvalChallenge(p.approval_id, actionDigest(action), bytes(p.nonce_b64));
        const verdict = verifyProof(
          { approverId: p.approver_id, credentialId: bytes(p.credential_id_b64), passkey: passkey.key, device: device.key },
          { credentialId: bytes(p.credential_id_b64), authenticatorData: bytes(p.authenticator_data_b64), clientDataJSON: bytes(p.client_data_json_b64), signature: bytes(p.signature_b64), deviceSignature: bytes(p.device_signature_b64) },
          { challenge, origin: rp.origin, rpId: rp.rpId, storedCounter: 0 },
        );
        if (!verdict.ok) return refused('bad_proof');
        const approvers = request.change === 'approver_add' ? [...this.copy.approvers, request.approver] : this.copy.approvers.filter((a) => a.id !== request.approver_id);
        this.copy = { domain: this.copy.domain, approvers };
        return { result: 'applied' };
      }
    }
  }
}
