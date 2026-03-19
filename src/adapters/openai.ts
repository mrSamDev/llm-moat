import type { SemanticClassifierAdapter } from "../types";
import { createOpenAICompatibleAdapter } from "./llm";
import { DEFAULT_CLASSIFICATION_PROMPT } from "./shared";

type OpenAIAdapterOptions = {
  apiKey: string;
  /** Default: "gpt-4o-mini" */
  model?: string;
  /** Default: DEFAULT_CLASSIFICATION_PROMPT */
  systemPrompt?: string;
  /** Your OpenAI organization ID, if applicable. */
  organization?: string;
};

/**
 * Semantic classifier adapter for the OpenAI API.
 *
 * Thin wrapper around createOpenAICompatibleAdapter with OpenAI-specific
 * defaults (gpt-4o-mini, https://api.openai.com/v1).
 *
 * Example:
 *   import { createOpenAIAdapter } from "prompt-defense/adapters/openai";
 *   const adapter = createOpenAIAdapter({ apiKey: process.env.OPENAI_API_KEY! });
 *   const result = await classifyWithAdapter(input, { adapter });
 */
export function createOpenAIAdapter(options: OpenAIAdapterOptions): SemanticClassifierAdapter {
  return createOpenAICompatibleAdapter({
    apiKey: options.apiKey,
    model: options.model ?? "gpt-4o-mini",
    baseURL: "https://api.openai.com/v1",
    systemPrompt: options.systemPrompt ?? DEFAULT_CLASSIFICATION_PROMPT,
    headers: options.organization ? { "openai-organization": options.organization } : undefined,
  });
}
