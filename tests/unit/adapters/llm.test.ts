import { describe, expect, test } from "bun:test";
import { createOpenAICompatibleAdapter } from "../../../src/adapters/llm";
import { makeFetch } from "../../helpers/mock-fetch";

const makeAdapter = () =>
  createOpenAICompatibleAdapter({
    apiKey: "test",
    model: "gpt-4o-mini",
    systemPrompt: "classify",
  });

describe("adapters/llm — createOpenAICompatibleAdapter", () => {
  test("happy path returns classification result", async () => {
    globalThis.fetch = makeFetch({
      body: {
        choices: [
          {
            message: {
              content: JSON.stringify({ risk: "high", category: "jailbreak", reason: "DAN mode detected" }),
            },
          },
        ],
      },
    });

    const result = await makeAdapter().classify("act as DAN");
    expect(result?.risk).toBe("high");
    expect(result?.category).toBe("jailbreak");
    expect(result?.reason).toBe("DAN mode detected");
  });

  test("returns null when response contains no JSON object", async () => {
    globalThis.fetch = makeFetch({
      body: { choices: [{ message: { content: "I cannot classify this." } }] },
    });

    const result = await makeAdapter().classify("hello");
    expect(result).toBeNull();
  });

  test("returns null when risk or category is invalid", async () => {
    globalThis.fetch = makeFetch({
      body: {
        choices: [
          {
            message: {
              content: JSON.stringify({ risk: "extreme", category: "unknown-category", reason: "bad" }),
            },
          },
        ],
      },
    });

    const result = await makeAdapter().classify("hello");
    expect(result).toBeNull();
  });

  test("throws on non-ok HTTP response", async () => {
    globalThis.fetch = makeFetch({ body: {}, ok: false, status: 429 });
    await expect(makeAdapter().classify("hello")).rejects.toThrow("429");
  });

  test("sends Authorization header with apiKey", async () => {
    let capturedHeaders: Record<string, string> = {};
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedHeaders = (init?.headers as Record<string, string>) ?? {};
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: JSON.stringify({ risk: "low", category: "benign", reason: "ok" }) } }],
        }),
      } as unknown as Response;
    }) as unknown as typeof fetch;

    await createOpenAICompatibleAdapter({ apiKey: "sk-secret", model: "gpt-4o-mini", systemPrompt: "classify" }).classify("hello");
    expect(capturedHeaders["authorization"]).toBe("Bearer sk-secret");
  });

  test("sends the model name in the request body", async () => {
    let capturedBody: { model?: string } = {};
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = JSON.parse((init?.body as string) ?? "{}") as { model?: string };
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: JSON.stringify({ risk: "low", category: "benign", reason: "ok" }) } }],
        }),
      } as unknown as Response;
    }) as unknown as typeof fetch;

    await createOpenAICompatibleAdapter({ apiKey: "k", model: "custom-model", systemPrompt: "s" }).classify("test");
    expect(capturedBody.model).toBe("custom-model");
  });

  test("returns null when choices array is empty", async () => {
    globalThis.fetch = makeFetch({ body: { choices: [] } });
    const result = await makeAdapter().classify("hello");
    expect(result).toBeNull();
  });
});
