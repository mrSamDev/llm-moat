import { describe, test, expect } from "bun:test";
import { LRUCache } from "../../src/cache.ts";

describe("LRUCache", () => {
  test("get returns undefined for missing key", () => {
    const cache = new LRUCache<string, number>();
    expect(cache.get("missing")).toBeUndefined();
  });

  test("set and get works", () => {
    const cache = new LRUCache<string, number>({ maxEntries: 10, defaultTtlMs: 5000 });
    cache.set("key1", 42);
    expect(cache.get("key1")).toBe(42);
  });

  test("entries expire based on TTL", async () => {
    const cache = new LRUCache<string, number>({ maxEntries: 10, defaultTtlMs: 50 });
    cache.set("expiring", 123);
    expect(cache.get("expiring")).toBe(123);
    
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(cache.get("expiring")).toBeUndefined();
  });

  test("custom TTL overrides default", async () => {
    const cache = new LRUCache<string, number>({ maxEntries: 10, defaultTtlMs: 500 });
    cache.set("short", 456, 50);
    expect(cache.get("short")).toBe(456);
    
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(cache.get("short")).toBeUndefined();
  });

  test("maxEntries eviction works (LRU)", () => {
    const cache = new LRUCache<string, number>({ maxEntries: 3 });
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("c", 3);
    cache.set("d", 4); // Should evict "a"
    
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("b")).toBe(2);
    expect(cache.get("c")).toBe(3);
    expect(cache.get("d")).toBe(4);
  });

  test("delete removes entry", () => {
    const cache = new LRUCache<string, number>();
    cache.set("toDelete", 999);
    expect(cache.delete("toDelete")).toBe(true);
    expect(cache.get("toDelete")).toBeUndefined();
  });

  test("delete returns false for missing key", () => {
    const cache = new LRUCache<string, number>();
    expect(cache.delete("missing")).toBe(false);
  });

  test("clear removes all entries", () => {
    const cache = new LRUCache<string, number>();
    cache.set("x", 1);
    cache.set("y", 2);
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get("x")).toBeUndefined();
    expect(cache.get("y")).toBeUndefined();
  });

  test("size returns current count", () => {
    const cache = new LRUCache<string, number>({ maxEntries: 10 });
    expect(cache.size).toBe(0);
    cache.set("a", 1);
    expect(cache.size).toBe(1);
    cache.set("b", 2);
    expect(cache.size).toBe(2);
  });

  test("prune removes expired entries", async () => {
    const cache = new LRUCache<string, number>({ maxEntries: 10, defaultTtlMs: 50 });
    cache.set("expire1", 1);
    cache.set("expire2", 2);
    cache.set("keep", 3, 5000);
    
    await new Promise((resolve) => setTimeout(resolve, 60));
    cache.prune();
    
    expect(cache.get("expire1")).toBeUndefined();
    expect(cache.get("expire2")).toBeUndefined();
    expect(cache.get("keep")).toBe(3);
  });
});
