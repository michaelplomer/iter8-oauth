package de.iter8.oauth.as;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * The in-memory stores refuse new entries when full rather than growing, and make room by dropping expired
 * entries first.
 */
class PendingStoreCapacityTests {

    @Test
    void the_pending_store_refuses_requests_when_full_of_live_ones() {
        PendingAuthorizationStore store = new PendingAuthorizationStore();
        for (int i = 0; i < PendingAuthorizationStore.MAX_PENDING; i++) {
            store.store(authorization(Instant.now().plusSeconds(60)));
        }

        assertThatThrownBy(() -> store.store(authorization(Instant.now().plusSeconds(60))))
                .isInstanceOf(StoreFullException.class);
    }

    @Test
    void the_pending_store_makes_room_by_dropping_expired_requests() {
        PendingAuthorizationStore store = new PendingAuthorizationStore();
        for (int i = 0; i < PendingAuthorizationStore.MAX_PENDING; i++) {
            store.store(authorization(Instant.now().minusSeconds(1)));
        }

        assertThat(store.store(authorization(Instant.now().plusSeconds(60)))).isNotBlank();
        assertThat(store.size()).isEqualTo(1);
    }

    @Test
    void the_consent_store_refuses_requests_when_full_of_live_ones() {
        ConsentStore store = new ConsentStore(Duration.ofMinutes(10));
        for (int i = 0; i < ConsentStore.MAX_PENDING; i++) {
            store.store(authorization(Instant.now().plusSeconds(60)), "binding");
        }

        assertThatThrownBy(() -> store.store(authorization(Instant.now().plusSeconds(60)), "binding"))
                .isInstanceOf(StoreFullException.class);
    }

    @Test
    void a_consent_is_only_released_to_the_browser_it_was_shown_in() {
        ConsentStore store = new ConsentStore(Duration.ofMinutes(10));
        String consentId = store.store(authorization(Instant.now().plusSeconds(60)), "right");

        assertThat(store.consume(consentId, "wrong")).isEmpty();
        // The failed attempt spent it.
        assertThat(store.consume(consentId, "right")).isEmpty();

        String another = store.store(authorization(Instant.now().plusSeconds(60)), "right");
        assertThat(store.consume(another, "right")).isPresent();
    }

    private static PendingAuthorization authorization(Instant expiresAt) {
        return new PendingAuthorization("google-oidc", "https://client.example.com/metadata.json", "Client",
                "https://client.example.com/callback", "state", "challenge", "none", "notes.read", null,
                expiresAt);
    }
}
