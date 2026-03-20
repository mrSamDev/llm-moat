import { afterEach, beforeAll, describe, expect, test } from "bun:test";
import { loadRuleSetFromUrl } from "../../src/rules";

const SAMPLE_JSON = JSON.stringify({
  rules: [{ id: "remote-test", patterns: ["inject"], risk: "high", category: "custom", reason: "remote test rule" }],
});

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

let sampleBuffer: ArrayBuffer;
let sha256Integrity: string;
let sha384Integrity: string;

beforeAll(async () => {
  const encoded = new TextEncoder().encode(SAMPLE_JSON);
  sampleBuffer = encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength);
  sha256Integrity = `sha256-${bufferToBase64(await crypto.subtle.digest("SHA-256", sampleBuffer))}`;
  sha384Integrity = `sha384-${bufferToBase64(await crypto.subtle.digest("SHA-384", sampleBuffer))}`;
});

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

function mockOkFetch(buffer: ArrayBuffer): void {
  globalThis.fetch = async () =>
    ({
      ok: true,
      status: 200,
      arrayBuffer: async () => buffer,
    }) as Response;
}

describe("loadRuleSetFromUrl", () => {
  test("loads rules with valid SHA-256 integrity", async () => {
    mockOkFetch(sampleBuffer);
    const rules = await loadRuleSetFromUrl("https://example.com/rules.json", { integrity: sha256Integrity });
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("remote-test");
  });

  test("loads rules with valid SHA-384 integrity", async () => {
    mockOkFetch(sampleBuffer);
    const rules = await loadRuleSetFromUrl("https://example.com/rules.json", { integrity: sha384Integrity });
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("remote-test");
  });

  test("throws on integrity mismatch", async () => {
    mockOkFetch(sampleBuffer);
    const wrongHash = sha256Integrity.replace(/.$/, sha256Integrity.endsWith("A") ? "B" : "A");
    await expect(
      loadRuleSetFromUrl("https://example.com/rules.json", { integrity: wrongHash }),
    ).rejects.toThrow("integrity mismatch");
  });

  test("throws when integrity is empty", async () => {
    mockOkFetch(sampleBuffer);
    await expect(loadRuleSetFromUrl("https://example.com/rules.json", { integrity: "" })).rejects.toThrow(
      "integrity is required",
    );
  });

  test("throws on malformed SRI string", async () => {
    mockOkFetch(sampleBuffer);
    await expect(
      loadRuleSetFromUrl("https://example.com/rules.json", { integrity: "not-a-valid-sri" }),
    ).rejects.toThrow("malformed integrity string");
  });

  test("throws on unsupported algorithm (sha1)", async () => {
    mockOkFetch(sampleBuffer);
    await expect(
      loadRuleSetFromUrl("https://example.com/rules.json", { integrity: "sha1-dGVzdA==" }),
    ).rejects.toThrow("unsupported algorithm sha1");
  });

  test("throws on network error", async () => {
    globalThis.fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    await expect(
      loadRuleSetFromUrl("https://example.com/rules.json", { integrity: sha256Integrity }),
    ).rejects.toThrow("network error");
  });

  test("throws on non-2xx HTTP status", async () => {
    globalThis.fetch = async () => ({ ok: false, status: 404 }) as Response;
    await expect(
      loadRuleSetFromUrl("https://example.com/rules.json", { integrity: sha256Integrity }),
    ).rejects.toThrow("HTTP 404");
  });
});
