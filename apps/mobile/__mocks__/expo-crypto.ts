// Jest manual mock for `expo-crypto`.
//
// Why this exists: expo-crypto's real implementation is a native module
// binding (iOS/Android). Requiring it outside a running Expo/React Native
// app throws at load time, so it can't be exercised by a plain Jest/Node
// test run. Jest auto-applies any `__mocks__/<package>` file placed
// adjacent to `node_modules` for node_modules packages — no explicit
// `jest.mock()` call needed — so every test in this project transparently
// gets this instead of the native module.
//
// This mock is backed by Node's own OS-sourced CSPRNG (`node:crypto`), not
// a custom/userspace entropy pool, so it preserves the property the real
// module provides (OS RNG only) rather than just papering over the missing
// native binding with something weaker.
import { randomBytes as nodeRandomBytes } from "node:crypto";

export function getRandomBytes(byteCount: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(byteCount));
}

export async function getRandomBytesAsync(byteCount: number): Promise<Uint8Array> {
  return getRandomBytes(byteCount);
}
