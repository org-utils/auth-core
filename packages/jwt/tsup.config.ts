import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],

  format: ["esm", "cjs"],

  target: "es2022",

  clean: true,

  splitting: false,

  sourcemap: true,

  treeshake: true,

  minify: true,

  dts: false,

  outExtension({ format }) {
    return {
      js: format === "esm" ? ".mjs" : ".js"
    };
  }
});
