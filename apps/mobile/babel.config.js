module.exports = function (api) {
  const isTest = api.env("test");
  api.cache(true);

  if (isTest) {
    // Jest runs under BABEL_ENV=test (set automatically by babel-jest). We
    // deliberately do NOT use babel-preset-expo for tests: it targets
    // Metro's bundler (which understands native ESM in node_modules and
    // needs no CommonJS conversion), whereas Jest's runtime needs plain
    // CommonJS. @babel/preset-env with an explicit `modules: "commonjs"`
    // target gives us that conversion directly and lets the same config
    // transform ESM-only node_modules dependencies (e.g. @noble/*,
    // @scure/*) when Jest is told to stop ignoring them — see
    // jest.config.js's transformIgnorePatterns.
    return {
      presets: [
        ["@babel/preset-env", { targets: { node: "current" }, modules: "commonjs" }],
        "@babel/preset-typescript",
      ],
    };
  }

  // Real Expo/Metro bundling (app start, EAS build, etc.).
  return {
    presets: ["babel-preset-expo"],
  };
};
