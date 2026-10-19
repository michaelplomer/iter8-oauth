package de.iter8.oauth.cimd;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A cache of fetched documents with a fixed size and per-entry expiry.
 *
 * <p>The keys are URLs chosen by clients, so anyone can add entries by inventing new URLs. A cache that only
 * ever replaced entries would therefore grow without limit. This one holds at most a fixed number: when it is
 * full it drops expired entries first and then the entries closest to expiring, which costs a refetch for a
 * legitimate client and nothing worse.
 *
 * @param <V> what is cached
 */
final class ExpiringCache<V> {

    private final int maxEntries;

    private final Map<String, Entry<V>> entries = new ConcurrentHashMap<>();

    /**
     * @param maxEntries how many entries the cache may hold
     */
    ExpiringCache(int maxEntries) {
        this.maxEntries = maxEntries;
    }

    /**
     * @param key the key
     * @return the cached value, or {@code null} when it is absent or has expired
     */
    V getFresh(String key) {
        Entry<V> entry = this.entries.get(key);
        if (entry == null) {
            return null;
        }
        if (Instant.now().isAfter(entry.expiresAt())) {
            this.entries.remove(key, entry);
            return null;
        }
        return entry.value();
    }

    /**
     * @param key the key
     * @param value the value
     * @param expiresAt when the value stops being reused
     */
    void put(String key, V value, Instant expiresAt) {
        if (this.entries.size() >= this.maxEntries && !this.entries.containsKey(key)) {
            makeRoom();
        }
        this.entries.put(key, new Entry<>(value, expiresAt));
    }

    /**
     * @param key the key to forget
     */
    void remove(String key) {
        this.entries.remove(key);
    }

    /**
     * @return how many entries are held, for tests
     */
    int size() {
        return this.entries.size();
    }

    private synchronized void makeRoom() {
        Instant now = Instant.now();
        this.entries.values().removeIf(entry -> now.isAfter(entry.expiresAt()));
        while (this.entries.size() >= this.maxEntries) {
            this.entries.entrySet().stream()
                    .min(Comparator.comparing(entry -> entry.getValue().expiresAt()))
                    .ifPresent(oldest -> this.entries.remove(oldest.getKey(), oldest.getValue()));
        }
    }

    private record Entry<V>(V value, Instant expiresAt) {
    }
}
