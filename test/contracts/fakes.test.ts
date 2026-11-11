// Every contract suite run against its fake (KBOX-35). Each adapter unit adds its own run of the same suite.
import { approvalsContract } from './approvals.contract.ts';
import { auditContract } from './audit.contract.ts';
import { destinationContract } from './destination.contract.ts';
import { issuerContract } from './issuer.contract.ts';
import { listerContract } from './lister.contract.ts';
import { redeployerContract } from './redeployer.contract.ts';
import { relayProfileContract } from './relay-profile.contract.ts';
import { vaultContract } from './vault.contract.ts';
import { verifierContract } from './verifier.contract.ts';
import { FakeApprovals } from '../fakes/approvals.ts';
import { FakeAudit } from '../fakes/audit.ts';
import { FakeDestination, FakeRedeployer } from '../fakes/destination.ts';
import { FakePlatformWorld } from '../fakes/platform.ts';
import { fakeRelayProfile } from '../fakes/relay-profile.ts';
import { FakeVault } from '../fakes/vault.ts';
import { lent, seededRandom, seedFor } from '../kit/index.ts';

const seed = seedFor(process.env);
const world = (): FakePlatformWorld => new FakePlatformWorld(seededRandom(seed));

vaultContract('fake', () => new FakeVault());

auditContract('fake', () => {
  const audit = new FakeAudit();
  return { audit, entries: () => audit.entries() };
});

approvalsContract('fake', () => {
  const approvals = new FakeApprovals();
  return { approvals, decide: (id, d) => approvals.decide(id, d) };
});

issuerContract('fake', () => {
  const w = world();
  return { issuer: w.issuer, master: w.master(), wrongMaster: w.stranger(), lister: w.lister };
});

listerContract('fake', () => {
  const w = world();
  return { issuer: w.issuer, lister: w.lister, master: w.master(), wrongMaster: w.stranger() };
});

verifierContract('fake', () => {
  const w = world();
  return { issuer: w.issuer, verifier: w.verifier, master: w.master(), stranger: w.stranger(), setUnreachable: (down) => w.setReachable(!down) };
});

destinationContract('fake', () => {
  const destination = new FakeDestination();
  const target = { kind: 'vercel-env', id: 'project-1' } as const;
  return {
    destination,
    target,
    master: lent(Buffer.from('master'), 'master:1'),
    valueOne: lent(Buffer.from('value-one'), 'k:1'),
    valueTwo: lent(Buffer.from('value-two'), 'k:2'),
    has: (name) => destination.has(target, name),
  };
});

redeployerContract('fake', () => {
  const redeployer = new FakeRedeployer();
  return { redeployer, target: { kind: 'vercel-env', id: 'project-1' }, master: lent(Buffer.from('master'), 'master:1'), failNext: () => redeployer.failNext() };
});

relayProfileContract('fake', () => fakeRelayProfile);
