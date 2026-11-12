// KBOX-23: the one mapping between the kind of a destination as the metadata and the actions spell it (`vercel_env`) and the kind of the
// adapter that serves it (`vercel-env`, `DestinationKind`). Total over the kinds an adapter serves: a new kind fails to compile until mapped.
import type { DestinationKind } from '../ports/destination.ts';
import type { Destination } from './actions.ts';

type AdapterBacked = Exclude<Destination['kind'], 'workstation'>;

const ADAPTER_KIND: Readonly<Record<AdapterBacked, DestinationKind>> = {
  vercel_env: 'vercel-env',
  gcp_secret: 'google-secret-manager',
  supabase_secret: 'supabase-secret',
};

/** The adapter kind that serves a metadata destination kind; undefined for the workstation (a delivery) and for text that is no kind. */
export const adapterKindOf = (kind: string): DestinationKind | undefined => (Object.hasOwn(ADAPTER_KIND, kind) ? ADAPTER_KIND[kind as AdapterBacked] : undefined);
