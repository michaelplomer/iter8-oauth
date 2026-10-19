package de.iter8.oauth.as;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds authorization requests while the user reads the consent page.
 *
 * <p>Each entry is bound to the browser the page was shown in. The page sets a cookie holding a random value,
 * and only a hash of that value is kept here. An approval counts only when the same value comes back, which
 * stops an attacker from starting a request in their own browser and tricking someone else's browser into
 * approving it: the victim's browser never received the attacker's cookie.
 *
 * <p>In memory and bounded, like the other pending stores. A full store refuses new requests rather than
 * growing, so a flood of authorization requests costs availability, not memory.
 */
public class ConsentStore {

    /** How many consent pages may be awaiting an answer at once. */
    static final int MAX_PENDING = 10_000;

    private final Map<String, PendingConsent> pending = new ConcurrentHashMap<>();

    private final Duration ttl;

    /**
     * @param ttl how long the user has to answer the consent page
     */
    public ConsentStore(Duration ttl) {
        this.ttl = ttl;
    }

    /**
     * Stores a request awaiting consent.
     *
     * @param authorization the validated request
     * @param browserBinding the random value set as a cookie in the browser showing the page
     * @return an unguessable identifier for the consent page's form
     * @throws StoreFullException when too many consent pages are awaiting an answer
     */
    public String store(PendingAuthorization authorization, String browserBinding) {
        if (this.pending.size() >= MAX_PENDING) {
            purgeExpired();
            if (this.pending.size() >= MAX_PENDING) {
                throw new StoreFullException("Too many consent pages are awaiting an answer.");
            }
        }
        String consentId = PendingAuthorizationStore.randomToken();
        this.pending.put(consentId, new PendingConsent(authorization, hash(browserBinding),
                Instant.now().plus(this.ttl)));
        return consentId;
    }

    /**
     * Takes a request back for a decision, if it is still there, still fresh, and the browser presenting it
     * is the one it was shown in.
     *
     * <p>Removal is unconditional, as with the other pending stores: an identifier presented once is spent,
     * even when the browser check fails, so a failed attempt cannot be retried with another guess.
     *
     * @param consentId the identifier from the consent page's form
     * @param browserBinding the value of the consent cookie the browser sent, or {@code null}
     * @return the request, or empty when it is unknown, expired, or presented by another browser
     */
    public Optional<PendingAuthorization> consume(String consentId, String browserBinding) {
        if (consentId == null) {
            return Optional.empty();
        }
        PendingConsent consent = this.pending.remove(consentId);
        if (consent == null || Instant.now().isAfter(consent.expiresAt()) || browserBinding == null) {
            return Optional.empty();
        }
        if (!MessageDigest.isEqual(consent.bindingHash(), hash(browserBinding))) {
            return Optional.empty();
        }
        return Optional.of(consent.authorization());
    }

    /**
     * @return how many consent pages are awaiting an answer, for tests and diagnostics
     */
    public int size() {
        purgeExpired();
        return this.pending.size();
    }

    /**
     * @return how long the user has to answer the consent page
     */
    public Duration ttl() {
        return this.ttl;
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        this.pending.values().removeIf(consent -> now.isAfter(consent.expiresAt()));
    }

    private static byte[] hash(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is required of every Java platform", impossible);
        }
    }

    private record PendingConsent(PendingAuthorization authorization, byte[] bindingHash, Instant expiresAt) {
    }
}
