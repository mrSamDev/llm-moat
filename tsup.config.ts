import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "adapters/llm": "src/adapters/llm.ts",
    "adapters/anthropic": "src/adapters/anthropic.ts",
    "adapters/openai": "src/adapters/openai.ts",
    "adapters/ollama": "src/adapters/ollama.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: false,
});
