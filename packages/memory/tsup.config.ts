import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],

  format: ["esm", "cjs"],

  target: "es2022",

  outDir: "dist",

  clean: false,       // tsc already generated .d.ts
  dts: false,         // declarations come from tsc

  splitting: false,   // library package
  sourcemap: true,
  treeshake: true,
  minify: true,

  platform: "node",


  external: [
    /^node:/,
    // Internal packages should remain external.
    /^@auth-core\//,
  ],

  outExtension({ format }) {
    return {
      js: format === "esm" ? ".mjs" : ".js",
    };
  },
});
