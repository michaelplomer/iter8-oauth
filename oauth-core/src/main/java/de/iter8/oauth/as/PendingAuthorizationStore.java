package de.iter8.oauth.as;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds authorization requests for the round trip through the upstream provider's consent screen.
 *
 * <p>The key is this server's own {@code state} for the upstream leg, which is unguessable and used once. The
 * client's own {@code state} is never reused for that purpose: it is the client's value, chosen by the
 * client, and treating it as a server-side secret would let a client fix the key to something it knows.
 *
 * <p>In memory, so a restart mid-consent loses the request and the user starts again. That is the right
 * trade for a value that lives for a minute; anything persistent here would be a database of half-finished
 * logins. (A shared store can replace this to allow more than one instance — see the deployment notes.)
 */
public class PendingAuthorizationStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Map<String, PendingAuthorization> pending = new ConcurrentHashMap<>();

    /**
     * Stores a request and returns the state to carry through the upstream provider.
     *
     * @param authorization the validated request
     * @return an unguessable state value
     */
    public String store(PendingAuthorization authorization) {
        purgeExpired();
        String state = randomToken();
        this.pending.put(state, authorization);
        return state;
    }

    /**
     * Takes a request back, if it is still there and still fresh.
     *
     * <p>Removal is unconditional: a state that has been presented once is spent, whether or not it turned
     * out to be usable. Leaving a consumed state in place would make the callback replayable.
     *
     * @param state the state returned by the upstream provider
     * @return the request, or empty when it is unknown or expired
     */
    public Optional<PendingAuthorization> consume(String state) {
        if (state == null) {
            return Optional.empty();
        }
        PendingAuthorization authorization = this.pending.remove(state);
        if (authorization == null || authorization.isExpired()) {
            return Optional.empty();
        }
        return Optional.of(authorization);
    }

    /**
     * @return how many requests are waiting, for tests and diagnostics
     */
    public int size() {
        purgeExpired();
        return this.pending.size();
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        this.pending.values().removeIf(authorization -> now.isAfter(authorization.expiresAt()));
    }

    /**
     * @return 256 bits of randomness, URL safe
     */
    static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * @param ttl how long a request stays usable
     * @return the instant it expires
     */
    public static Instant expiryFrom(Duration ttl) {
        return Instant.now().plus(ttl);
    }
}
