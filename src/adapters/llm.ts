/**
 * OpenAI-compatible semantic classifier adapter primitives for providers that
 * expose a `/chat/completions` style API.
 */
import type { ClassificationResult, SemanticClassifierAdapter } from "../types.ts";
import { DEFAULT_CLASSIFICATION_PROMPT, parseClassifierJson } from "./shared.ts";

/** Configuration for any OpenAI-compatible semantic classifier provider. */
type OpenAICompatibleAdapterOptions = {
  apiKey: string;
  model: string;
  baseURL?: string;
  systemPrompt?: string;
  headers?: Record<string, string>;
};

/** Minimal shape of a chat completion response used by this adapter. */
type ChatCompletionResponse = {
  choices?: Array<{
    message?: {
      content?: string | Array<{ type?: string; text?: string }>;
    };
  }>;
};

type MessageContent = string | Array<{ type?: string; text?: string }> | undefined;

function extractTextContent(content: MessageContent): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((part) => part.text ?? "").join("");
}

export function createOpenAICompatibleAdapter(
  options: OpenAICompatibleAdapterOptions,
): SemanticClassifierAdapter {
  const systemPrompt = options.systemPrompt ?? DEFAULT_CLASSIFICATION_PROMPT;

  return {
    async classify(canonicalInput: string): Promise<Partial<ClassificationResult> | null> {
      const response = await fetch(`${options.baseURL ?? "https://api.openai.com/v1"}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${options.apiKey}`,
          ...options.headers,
        },
        body: JSON.stringify({
          model: options.model,
          temperature: 0,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: canonicalInput },
          ],
        }),
      });

      if (!response.ok) {
        throw new Error(`Semantic classifier request failed with ${response.status}`);
      }

      const parsed = (await response.json()) as ChatCompletionResponse;
      const text = extractTextContent(parsed.choices?.[0]?.message?.content).trim();
      return parseClassifierJson(text);
    },
  };
}
