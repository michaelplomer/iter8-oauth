package de.iter8.oauth.cimd;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.Test;

class ExpiringCacheTests {

    @Test
    void never_holds_more_than_its_limit() {
        ExpiringCache<String> cache = new ExpiringCache<>(3);
        for (int i = 0; i < 10; i++) {
            cache.put("https://client" + i + ".example.com/metadata.json", "document",
                    Instant.now().plusSeconds(60 + i));
        }

        assertThat(cache.size()).isEqualTo(3);
        // The entries closest to expiring were the ones dropped.
        assertThat(cache.getFresh("https://client9.example.com/metadata.json")).isEqualTo("document");
        assertThat(cache.getFresh("https://client0.example.com/metadata.json")).isNull();
    }

    @Test
    void drops_expired_entries_before_live_ones() {
        ExpiringCache<String> cache = new ExpiringCache<>(2);
        cache.put("expired", "old", Instant.now().minusSeconds(1));
        cache.put("live", "current", Instant.now().plusSeconds(60));

        cache.put("new", "fresh", Instant.now().plusSeconds(60));

        assertThat(cache.getFresh("live")).isEqualTo("current");
        assertThat(cache.getFresh("new")).isEqualTo("fresh");
        assertThat(cache.getFresh("expired")).isNull();
    }
}
