/**
 * Utilities for mocking globalThis.fetch in adapter tests.
 */

export interface MockResponseInit {
  body: unknown;
  ok?: boolean;
  status?: number;
}

export function makeFetch({ body, ok = true, status = 200 }: MockResponseInit): typeof fetch {
  return (async () =>
    ({
      ok,
      status,
      json: async () => body,
    }) as unknown as Response) as unknown as typeof fetch;
}

export function makeCapturingFetch(responseBody: unknown) {
  let capturedUrl = "";
  let capturedBody: Record<string, unknown> = {};
  let capturedHeaders: Record<string, string> = {};

  const fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    capturedUrl = url as string;
    capturedBody = JSON.parse((init?.body as string) ?? "{}") as Record<string, unknown>;
    const headers = init?.headers as Record<string, string> | undefined;
    capturedHeaders = headers ?? {};
    return {
      ok: true,
      status: 200,
      json: async () => responseBody,
    } as unknown as Response;
  }) as unknown as typeof globalThis.fetch;

  return { fetch, get url() { return capturedUrl; }, get body() { return capturedBody; }, get headers() { return capturedHeaders; } };
}

/** Install a mock fetch for the duration of a test and restore afterwards. */
export function withMockFetch(init: MockResponseInit, fn: () => Promise<void>): Promise<void> {
  const original = globalThis.fetch;
  globalThis.fetch = makeFetch(init);
  return fn().finally(() => {
    globalThis.fetch = original;
  });
}

/** Build a minimal OpenAI-format success response body. */
export function openAIResponse(content: string) {
  return {
    choices: [{ message: { content } }],
  };
}
