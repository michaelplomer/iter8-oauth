package de.iter8.oauth.as;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Makes refresh tokens single-use and revokes a family when one of its tokens is replayed.
 *
 * <p>Each refresh spends the presented token and issues a new one in the same family. A legitimate client
 * only ever holds the newest token, so a token presented a second time was copied, and nobody can tell from
 * here whether the copy or the original is in the right hands. The whole family is therefore revoked, which
 * ends the authorization for both, and the user signs in again. This is the refresh token rotation with
 * reuse detection that OAuth 2.1 recommends for public clients.
 *
 * <p>In memory, like the other stores, and bounded. A restart forgets which tokens were spent, so a token
 * used before the restart can be used once more after it. Spent entries are kept until the token would have
 * expired anyway; a revoked family is kept for as long as any token in it could still be valid.
 */
public class RefreshTokenLedger {

    /** How many spent tokens are remembered at once. */
    static final int MAX_SPENT = 100_000;

    private final Map<String, Instant> spent = new ConcurrentHashMap<>();

    private final Map<String, Instant> revokedFamilies = new ConcurrentHashMap<>();

    private final Duration refreshTokenTtl;

    /**
     * @param refreshTokenTtl how long an issued refresh token is valid, which bounds how long a revoked
     *     family has to be remembered
     */
    public RefreshTokenLedger(Duration refreshTokenTtl) {
        this.refreshTokenTtl = refreshTokenTtl;
    }

    /** What happened when a refresh token was presented. */
    public enum Outcome {

        /** The token had not been used before and is now spent. */
        FIRST_USE,

        /** The token had been used before; its family is now revoked. */
        REUSED,

        /** The token's family was revoked earlier. */
        REVOKED
    }

    /**
     * Spends a refresh token.
     *
     * @param tokenId the token's identifier
     * @param familyId its family's identifier
     * @param expiresAt when the token expires, after which it no longer needs remembering
     * @return whether this was the token's first use
     * @throws StoreFullException when too many spent tokens are being remembered
     */
    public Outcome spend(String tokenId, String familyId, Instant expiresAt) {
        Instant now = Instant.now();
        Instant revokedUntil = this.revokedFamilies.get(familyId);
        if (revokedUntil != null && now.isBefore(revokedUntil)) {
            return Outcome.REVOKED;
        }
        if (this.spent.size() >= MAX_SPENT) {
            purgeExpired();
            if (this.spent.size() >= MAX_SPENT) {
                throw new StoreFullException("Too many spent refresh tokens are being remembered.");
            }
        }
        if (this.spent.putIfAbsent(tokenId, expiresAt) != null) {
            this.revokedFamilies.put(familyId, now.plus(this.refreshTokenTtl));
            return Outcome.REUSED;
        }
        return Outcome.FIRST_USE;
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        this.spent.values().removeIf(now::isAfter);
        this.revokedFamilies.values().removeIf(now::isAfter);
    }
}
