// Entry point. package.json's "main" points here rather than at
// "expo/AppEntry" directly: on Windows, resolving that bare specifier for
// the manifest's mainModuleName produced a backslash-separated path
// (node_modules\expo\AppEntry) instead of forward slashes, which Expo Go's
// own manifest validation rejects as "unresolvable" — a local, relative
// entry file avoids that resolution path entirely. Mirrors
// node_modules/expo/AppEntry.js's own two lines exactly.
//
// "fast-text-encoding" MUST be the first import in this file, before
// anything else — Hermes (React Native's JS engine) does not provide
// TextDecoder globally (found live: exporting an identity/session crashed
// with "Property 'TextDecoder' doesn't exist" — TextEncoder happens to
// already work on this Hermes build, TextDecoder does not, an asymmetry
// specific to this engine, not something Jest's Node-based test runner
// ever exercises, which is why every prior test suite passed clean while
// this was broken on-device). This package self-installs both
// TextEncoder/TextDecoder onto `global` as a side effect of being
// imported, only filling in what's actually missing — every module below
// (crypto, identity, sessionauth, fileobjects, onboarding, vault, several
// of which call `new TextEncoder()`/`new TextDecoder()` at module-load
// time, not just inside functions) depends on this having already run.
import "fast-text-encoding";

import { registerRootComponent } from "expo";

import App from "./App";

registerRootComponent(App);
