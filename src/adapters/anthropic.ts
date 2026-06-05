/**
 * Anthropic adapter entrypoint for semantic prompt-injection classification.
 */
import type { AdapterClassificationResult, ClassificationResult, SemanticClassifierAdapter } from "../types.ts";
import { DEFAULT_CLASSIFICATION_PROMPT, parseClassifierJson, withTimeout } from "./shared.ts";

/** Minimal Anthropic client contract required by the adapter. */
type AnthropicClient = {
  messages: {
    create(params: {
      model: string;
      max_tokens: number;
      system?: string;
      messages: Array<{ role: string; content: string }>;
      signal?: AbortSignal;
    }): Promise<{
      content: Array<{ type: string; text?: string }>;
    }>;
  };
};

/** Options for creating an Anthropic-backed semantic classifier adapter. */
type AnthropicAdapterOptions = {
  client: AnthropicClient;
  /** Default: "claude-haiku-4-5-20251001" */
  model?: string;
  /** Default: DEFAULT_CLASSIFICATION_PROMPT */
  systemPrompt?: string;
  /** Abort the request after this many milliseconds. Default: 30000. */
  timeoutMs?: number;
};

/** Creates a semantic classifier adapter backed by the Anthropic Messages API. */
export function createAnthropicAdapter(options: AnthropicAdapterOptions): SemanticClassifierAdapter {
  const model = options.model ?? "claude-haiku-4-5-20251001";
  const systemPrompt = options.systemPrompt ?? DEFAULT_CLASSIFICATION_PROMPT;

  return {
    async classify(canonicalInput: string): Promise<AdapterClassificationResult | null> {
      const timeoutMs = options.timeoutMs ?? 30_000;

      const response = await withTimeout(timeoutMs, async (signal) =>
        options.client.messages.create({
          model,
          max_tokens: 256,
          system: systemPrompt,
          messages: [{ role: "user", content: canonicalInput }],
          signal,
        }),
      );

      const text = response.content
        .filter((block) => block.type === "text")
        .map((block) => block.text ?? "")
        .join("")
        .trim();

      return parseClassifierJson(text);
    },
  };
}
