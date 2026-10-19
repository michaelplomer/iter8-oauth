package de.iter8.oauth.as;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds the authorization codes this server has issued.
 *
 * <p>A code must be redeemable exactly once, and single use cannot be expressed in a self-contained value:
 * anything the client holds, the client can present twice. Access and refresh tokens carry their own
 * contents; only the identifiers of spent refresh tokens are remembered, by {@link RefreshTokenLedger}.
 *
 * <p>Codes live for about a minute, so the store is small by construction, and losing it on a restart costs
 * whoever was mid-authorization one retry. It is bounded all the same, and only swept for expired codes when
 * it fills up.
 */
public class AuthorizationCodeStore {

    /** How many issued codes may be awaiting redemption at once. */
    static final int MAX_CODES = 10_000;

    private final Map<String, IssuedAuthorizationCode> codes = new ConcurrentHashMap<>();

    /**
     * @param code the authorization code to remember
     * @return the code value to hand the client
     */
    public String store(IssuedAuthorizationCode code) {
        if (this.codes.size() >= MAX_CODES) {
            purgeExpired();
            if (this.codes.size() >= MAX_CODES) {
                throw new StoreFullException("Too many authorization codes are awaiting redemption.");
            }
        }
        String value = PendingAuthorizationStore.randomToken();
        this.codes.put(value, code);
        return value;
    }

    /**
     * Redeems an authorization code, which may happen exactly once.
     *
     * @param value the code from the token request
     * @return the code's details, or empty when it is unknown, spent or expired
     */
    public Optional<IssuedAuthorizationCode> redeem(String value) {
        if (value == null) {
            return Optional.empty();
        }
        IssuedAuthorizationCode code = this.codes.remove(value);
        if (code == null || code.isExpired()) {
            return Optional.empty();
        }
        return Optional.of(code);
    }

    /**
     * @return how many codes are outstanding, for tests and diagnostics
     */
    public int size() {
        purgeExpired();
        return this.codes.size();
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        this.codes.values().removeIf(code -> now.isAfter(code.expiresAt()));
    }
}
