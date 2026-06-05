/**
 * Simple LRU cache with TTL support for adapter results.
 */

type CacheEntry<T> = {
  value: T;
  expiresAt: number;
};

export type CacheOptions = {
  /** Maximum number of entries to cache. Default: 1000 */
  maxEntries?: number;
  /** Default TTL in milliseconds. Default: 5 minutes */
  defaultTtlMs?: number;
};

/**
 * LRU cache with time-based expiration.
 * Automatically evicts oldest entries when maxEntries is reached.
 * Entries expire based on TTL, not access time.
 */
export class LRUCache<K, V> {
  private readonly cache = new Map<K, CacheEntry<V>>();
  private readonly maxEntries: number;
  private readonly defaultTtlMs: number;

  // fallow-ignore-next-line complexity
  constructor(options?: CacheOptions) {
    this.maxEntries = options?.maxEntries ?? 1000;
    this.defaultTtlMs = options?.defaultTtlMs ?? 5 * 60 * 1000; // 5 minutes
  }

  /**
   * Get a value from the cache. Returns undefined if not found or expired.
   * Updates access order so the entry is treated as recently used.
   */
  get(key: K): V | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    // Move to end to mark as recently used
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.value;
  }

  /**
   * Set a value in the cache with optional custom TTL.
   * Evicts oldest entry if cache is full.
   */
  set(key: K, value: V, ttlMs?: number): void {
    // Evict oldest if at capacity
    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + (ttlMs ?? this.defaultTtlMs),
    });
  }

  /** Clear all entries from the cache. */
  clear(): void {
    this.cache.clear();
  }

  /** Remove a specific entry from the cache. */
  delete(key: K): boolean {
    return this.cache.delete(key);
  }

  /** Get the current number of entries (may include expired). */
  get size(): number {
    return this.cache.size;
  }

  /** Remove all expired entries. Call periodically for cleanup. */
  prune(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }
}
