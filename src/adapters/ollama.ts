/**
 * Ollama adapter entrypoint for local semantic prompt-injection classification.
 */
import type { SemanticClassifierAdapter } from "../types";
import { createOpenAICompatibleAdapter } from "./llm";
import { DEFAULT_CLASSIFICATION_PROMPT } from "./shared";

/** Options for creating an Ollama-backed semantic classifier adapter. */
type OllamaAdapterOptions = {
  /**
   * The Ollama model to use. Must be pulled locally first (`ollama pull <model>`).
   * Examples: "llama3.2", "mistral", "gemma2", "phi3", "qwen2.5"
   */
  model: string;
  /** Default: "http://localhost:11434" */
  baseURL?: string;
  /** Default: DEFAULT_CLASSIFICATION_PROMPT */
  systemPrompt?: string;
};

/**
 * Semantic classifier adapter for a locally running Ollama instance.
 *
 * Ollama exposes an OpenAI-compatible API at /v1/chat/completions. No API key
 * required — Ollama runs entirely locally.
 *
 * Prerequisites:
 *   1. Install Ollama: https://ollama.com
 *   2. Pull a model: ollama pull llama3.2
 *   3. Ollama runs on http://localhost:11434 by default
 *
 * Example:
 *   import { createOllamaAdapter } from "prompt-defense/adapters/ollama";
 *   const adapter = createOllamaAdapter({ model: "llama3.2" });
 *   const result = await classifyWithAdapter(input, { adapter });
 *
 * Model recommendations for classification:
 *   - llama3.2 (3B)  — fast, good JSON output
 *   - mistral (7B)   — strong instruction following
 *   - gemma2 (9B)    — reliable JSON, accurate classification
 *   - phi3 (3.8B)    — efficient, good for low-resource environments
 */
export function createOllamaAdapter(options: OllamaAdapterOptions): SemanticClassifierAdapter {
  const baseURL = (options.baseURL ?? "http://localhost:11434").replace(/\/$/, "");

  return createOpenAICompatibleAdapter({
    apiKey: "ollama", // Ollama requires a non-empty string but ignores the value
    model: options.model,
    baseURL: `${baseURL}/v1`,
    systemPrompt: options.systemPrompt ?? DEFAULT_CLASSIFICATION_PROMPT,
  });
}
