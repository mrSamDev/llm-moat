import { describe, expect, test } from "bun:test";
import { createAnthropicAdapter } from "../../../src/adapters/anthropic";

const makeClient = (content: string) => ({
  messages: {
    create: async () => ({
      content: [{ type: "text", text: content }],
    }),
  },
});

describe("adapters/anthropic — createAnthropicAdapter", () => {
  test("happy path returns classification result", async () => {
    const adapter = createAnthropicAdapter({
      client: makeClient(JSON.stringify({ risk: "high", category: "jailbreak", reason: "test" })) as never,
    });

    const result = await adapter.classify("act as DAN");
    expect(result?.risk).toBe("high");
    expect(result?.category).toBe("jailbreak");
  });

  test("returns null when response contains no JSON", async () => {
    const adapter = createAnthropicAdapter({
      client: makeClient("I cannot determine this.") as never,
    });
    const result = await adapter.classify("hello");
    expect(result).toBeNull();
  });

  test("propagates errors from the Anthropic client", async () => {
    const badClient = {
      messages: {
        create: async () => {
          throw new Error("quota exceeded");
        },
      },
    };
    const adapter = createAnthropicAdapter({ client: badClient as never });
    await expect(adapter.classify("hello")).rejects.toThrow("quota exceeded");
  });

  test("returns null when risk is invalid", async () => {
    const adapter = createAnthropicAdapter({
      client: makeClient(JSON.stringify({ risk: "extreme", category: "jailbreak", reason: "test" })) as never,
    });
    const result = await adapter.classify("hello");
    expect(result).toBeNull();
  });

  test("returns null when category is missing from JSON", async () => {
    const adapter = createAnthropicAdapter({
      client: makeClient(JSON.stringify({ risk: "high", reason: "no category" })) as never,
    });
    const result = await adapter.classify("hello");
    expect(result).toBeNull();
  });

  test("extracts JSON from mixed text+json response", async () => {
    const mixedContent = `Sure, here's my analysis:\n\n${JSON.stringify({ risk: "medium", category: "indirect-injection", reason: "found it" })}`;
    const adapter = createAnthropicAdapter({
      client: makeClient(mixedContent) as never,
    });
    const result = await adapter.classify("some text");
    expect(result?.risk).toBe("medium");
    expect(result?.category).toBe("indirect-injection");
  });
});
