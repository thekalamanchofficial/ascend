// Entry point. package.json's "main" points here rather than at
// "expo/AppEntry" directly: on Windows, resolving that bare specifier for
// the manifest's mainModuleName produced a backslash-separated path
// (node_modules\expo\AppEntry) instead of forward slashes, which Expo Go's
// own manifest validation rejects as "unresolvable" — a local, relative
// entry file avoids that resolution path entirely. Mirrors
// node_modules/expo/AppEntry.js's own two lines exactly.
import { registerRootComponent } from "expo";

import App from "./App";

registerRootComponent(App);
