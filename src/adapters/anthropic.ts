import type { ClassificationResult, SemanticClassifierAdapter } from "../types";
import { DEFAULT_CLASSIFICATION_PROMPT, parseClassifierJson } from "./shared";

type AnthropicClient = {
  messages: {
    create(params: {
      model: string;
      max_tokens: number;
      system?: string;
      messages: Array<{ role: string; content: string }>;
    }): Promise<{
      content: Array<{ type: string; text?: string }>;
    }>;
  };
};

type AnthropicAdapterOptions = {
  client: AnthropicClient;
  /** Default: "claude-haiku-4-5-20251001" */
  model?: string;
  /** Default: DEFAULT_CLASSIFICATION_PROMPT */
  systemPrompt?: string;
};

export function createAnthropicAdapter(options: AnthropicAdapterOptions): SemanticClassifierAdapter {
  const model = options.model ?? "claude-haiku-4-5-20251001";
  const systemPrompt = options.systemPrompt ?? DEFAULT_CLASSIFICATION_PROMPT;

  return {
    async classify(canonicalInput: string): Promise<Partial<ClassificationResult> | null> {
      const response = await options.client.messages.create({
        model,
        max_tokens: 256,
        system: systemPrompt,
        messages: [{ role: "user", content: canonicalInput }],
      });

      const text = response.content
        .filter((block) => block.type === "text")
        .map((block) => block.text ?? "")
        .join("")
        .trim();

      return parseClassifierJson(text);
    },
  };
}
