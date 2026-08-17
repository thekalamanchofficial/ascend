// Local persistence for the onboarding/session-bootstrap flow's own
// bookkeeping — NOT a capability in its own right (apps/mobile/README.md:
// "no capability logic of its own"). This is composition-layer state:
// which identity/device this install currently is, and its last-issued
// session, held via Cryptography & Keys' `secureLocalStore`/
// `secureLocalRetrieve` (the same on-device encrypted storage every other
// capability's local persistence goes through) rather than inventing a
// second storage mechanism.
//
// Deliberately excluded from here, always: the recovery phrase (shown once
// by generateIdentityKeyMaterial, never persisted anywhere — see
// cryptography-and-keys.charter.md and crypto/index.ts's own doc comment)
// and any private key material (only ever referenced by opaque KeyHandle,
// which this module never stores — key handles are process-lifetime-only
// by construction; see keyRegistry.ts).
import { secureLocalStore, secureLocalRetrieve } from "../../capabilities/crypto/secureStore";

const LOCAL_IDENTITY_KEY = "ascend.onboarding.localIdentity";
const LOCAL_SESSION_KEY = "ascend.onboarding.localSession";

/**
 * This install's view of "who am I, on which device." `epoch` is tracked
 * here specifically because BindDevice's authorizationProof must be signed
 * against the identity's current epoch (see
 * apps/mobile/src/capabilities/identity/index.ts's buildBindDeviceMessage
 * doc comment) and identity.proto exposes epoch only in mutation
 * responses, not as a value fetchable from anywhere else. Updated after
 * every successful bind/revoke this device itself performs or is party to.
 */
export interface LocalIdentityRecord {
  identityRef: string;
  displayName: string;
  deviceId: string;
  epoch: number;
}

export interface LocalSessionRecord {
  sessionToken: string;
  expiresAtUnix: number;
}

function encode(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function decode<T>(bytes: Uint8Array): T {
  return JSON.parse(new TextDecoder().decode(bytes)) as T;
}

export async function saveLocalIdentity(record: LocalIdentityRecord): Promise<void> {
  await secureLocalStore(LOCAL_IDENTITY_KEY, encode(record));
}

export async function loadLocalIdentity(): Promise<LocalIdentityRecord | null> {
  try {
    return decode<LocalIdentityRecord>(await secureLocalRetrieve(LOCAL_IDENTITY_KEY));
  } catch {
    return null;
  }
}

export async function saveLocalSession(record: LocalSessionRecord): Promise<void> {
  await secureLocalStore(LOCAL_SESSION_KEY, encode(record));
}

export async function loadLocalSession(): Promise<LocalSessionRecord | null> {
  try {
    return decode<LocalSessionRecord>(await secureLocalRetrieve(LOCAL_SESSION_KEY));
  } catch {
    return null;
  }
}
