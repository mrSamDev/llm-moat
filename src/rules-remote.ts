import type { RuleDefinition, RuleSetJson } from "./types.ts";

const SRI_ALGORITHMS: Record<string, string> = {
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};

function parseSriHash(integrity: string): { algorithm: string; expected: string } {
  const match = integrity.match(/^(sha\d+)-([A-Za-z0-9+/]+=*)$/);
  if (!match) throw new Error(`loadRuleSetFromUrl: malformed integrity string`);
  const [, prefix, expected] = match;
  const algorithm = SRI_ALGORITHMS[prefix];
  if (!algorithm) throw new Error(`loadRuleSetFromUrl: unsupported algorithm ${prefix}`);
  return { algorithm, expected };
}

// fallow-ignore-next-line code-duplication
function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

const DEFAULT_RETRIES = 2;
const DEFAULT_RETRY_DELAY_MS = 100;

/**
 * Fetch a rule set from a URL with SRI integrity verification.
 * Requires Node >= 18 (globalThis.crypto.subtle).
 * Throws descriptively on network errors, integrity mismatches, and invalid rule sets.
 */
// fallow-ignore-next-line complexity
export async function loadRuleSetFromUrl(
  url: string,
  opts: { integrity: string; signal?: AbortSignal; retries?: number; retryDelayMs?: number },
): Promise<RuleDefinition[]> {
  if (!opts.integrity) throw new Error("loadRuleSetFromUrl: integrity is required");
  const { algorithm, expected } = parseSriHash(opts.integrity);

  const maxRetries = opts.retries ?? DEFAULT_RETRIES;
  const retryDelayMs = opts.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;

  let lastError: Error | null = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const res = await fetch(url, { signal: opts.signal });

      if (!res.ok) throw new Error(`loadRuleSetFromUrl: HTTP ${res.status} from ${url}`);

      const buffer = await res.arrayBuffer();
      const hashBuffer = await globalThis.crypto.subtle.digest(algorithm, buffer);
      const actual = bufferToBase64(hashBuffer);
      if (actual !== expected) throw new Error("loadRuleSetFromUrl: integrity mismatch");

      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
      } catch {
        throw new Error("loadRuleSetFromUrl: response is not valid UTF-8");
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new Error("loadRuleSetFromUrl: response is not valid JSON");
      }

      // Import here to avoid circular dependency at module level
      const { loadRuleSetFromJson } = await import("./rules.ts");
      return loadRuleSetFromJson(parsed as Parameters<typeof loadRuleSetFromJson>[0]);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));

      // Don't retry on integrity mismatch or validation errors (will fail again)
      if (
        lastError.message.includes("integrity mismatch") ||
        lastError.message.includes("UTF-8") ||
        lastError.message.includes("JSON")
      ) {
        throw lastError;
      }

      // Don't retry on network errors if no retries left
      if (attempt >= maxRetries) break;

      // Exponential backoff: 100ms, 200ms, 400ms...
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs * Math.pow(2, attempt)));
    }
  }

  throw lastError || new Error(`loadRuleSetFromUrl: failed after ${maxRetries + 1} attempts`);
}