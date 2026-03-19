import { describe, expect, test } from "bun:test";
import { createOpenAIAdapter } from "../../../src/adapters/openai";
import { DEFAULT_CLASSIFICATION_PROMPT } from "../../../src/adapters/shared";
import { makeFetch } from "../../helpers/mock-fetch";

const successBody = (content: string) => ({
  choices: [{ message: { content } }],
});

describe("adapters/openai — createOpenAIAdapter", () => {
  test("uses gpt-4o-mini by default and returns classification", async () => {
    let capturedBody: { model?: string } = {};
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = JSON.parse((init?.body as string) ?? "{}") as { model?: string };
      return {
        ok: true,
        json: async () => successBody(JSON.stringify({ risk: "high", category: "jailbreak", reason: "DAN" })),
      } as unknown as Response;
    }) as unknown as typeof fetch;

    const adapter = createOpenAIAdapter({ apiKey: "sk-test" });
    const result = await adapter.classify("act as DAN");
    expect(result?.risk).toBe("high");
    expect(capturedBody.model).toBe("gpt-4o-mini");
  });

  test("respects custom model override", async () => {
    let capturedBody: { model?: string } = {};
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = JSON.parse((init?.body as string) ?? "{}") as { model?: string };
      return {
        ok: true,
        json: async () => successBody(JSON.stringify({ risk: "low", category: "benign", reason: "ok" })),
      } as unknown as Response;
    }) as unknown as typeof fetch;

    await createOpenAIAdapter({ apiKey: "sk-test", model: "gpt-4o" }).classify("hello");
    expect(capturedBody.model).toBe("gpt-4o");
  });

  test("DEFAULT_CLASSIFICATION_PROMPT is the shared prompt", () => {
    expect(DEFAULT_CLASSIFICATION_PROMPT).toContain("prompt injection classifier");
  });

  test("throws on non-ok response", async () => {
    globalThis.fetch = makeFetch({ body: {}, ok: false, status: 401 });
    await expect(createOpenAIAdapter({ apiKey: "sk-test" }).classify("hello")).rejects.toThrow("401");
  });

  test("sends Authorization header", async () => {
    let capturedHeaders: Record<string, string> = {};
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = (init?.headers as Record<string, string>) ?? {};
      return {
        ok: true,
        json: async () => successBody(JSON.stringify({ risk: "low", category: "benign", reason: "ok" })),
      } as unknown as Response;
    }) as unknown as typeof fetch;
    await createOpenAIAdapter({ apiKey: "my-key" }).classify("test");
    expect(capturedHeaders["authorization"]).toBe("Bearer my-key");
  });

  test("sends organization header when provided", async () => {
    let capturedHeaders: Record<string, string> = {};
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = (init?.headers as Record<string, string>) ?? {};
      return {
        ok: true,
        json: async () => successBody(JSON.stringify({ risk: "low", category: "benign", reason: "ok" })),
      } as unknown as Response;
    }) as unknown as typeof fetch;
    await createOpenAIAdapter({ apiKey: "k", organization: "org-123" }).classify("test");
    expect(capturedHeaders["openai-organization"]).toBe("org-123");
  });

  test("returns null for invalid category in response", async () => {
    globalThis.fetch = (async () =>
      ({
        ok: true,
        json: async () => successBody(JSON.stringify({ risk: "high", category: "not-a-real-category", reason: "x" })),
      }) as unknown as Response) as unknown as typeof fetch;
    const result = await createOpenAIAdapter({ apiKey: "k" }).classify("hello");
    expect(result).toBeNull();
  });
});
