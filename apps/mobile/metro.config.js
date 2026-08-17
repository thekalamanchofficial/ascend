// Explicit Metro config, pinning projectRoot to this directory.
//
// Without this file, Expo's default config walks up looking for a
// "workspace root" and finds this repo's .git directory two levels up
// (ascend/), then treats ascend/ as a potential monorepo root and widens
// watchFolders/asset resolution accordingly — even though ascend/ has no
// root package.json or node_modules of its own (this is not an npm/pnpm
// workspace, just a git repo with apps/mobile nested inside it). That
// mismatch produced a doubled-relative-path asset resolution failure
// ("./../../node_modules/react-native/Libraries/LogBox/UI/LogBoxImages/
// close.png could not be found") when Expo Go tried to render its LogBox
// error overlay. Pinning projectRoot here stops that upward walk.
const { getDefaultConfig } = require("expo/metro-config");

const config = getDefaultConfig(__dirname);

module.exports = config;
