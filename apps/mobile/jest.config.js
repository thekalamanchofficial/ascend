/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "node",
  transform: {
    "^.+\\.(t|j)sx?$": "babel-jest",
  },
  // @noble/* and @scure/* ship as ESM-only packages ("type": "module", no
  // CommonJS build). Jest ignores node_modules transforms by default, which
  // would leave their `import`/`export` syntax untranspiled and unusable
  // under Jest's CJS runtime. Carve out just those two scopes rather than
  // transforming all of node_modules (keeps test runs fast).
  transformIgnorePatterns: ["node_modules/(?!(@noble|@scure)/)"],
  moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json"],
  testMatch: ["**/__tests__/**/*.test.ts"],
};
