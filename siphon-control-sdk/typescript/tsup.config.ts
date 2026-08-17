import { defineConfig } from "tsup";

// Dual ESM + CJS build with `.d.ts` (ESM) and `.d.cts` (CJS) type outputs, so
// the package resolves cleanly under both `import` and `require` (see the
// `exports` map in package.json). `ws` stays external — it is a runtime dep the
// consumer installs, not something to bundle.
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  target: "node18",
  external: ["ws"],
});
