package de.iter8.oauth.as;

import java.time.Duration;

/**
 * The authorization server's own timing knobs, independent of any provider. The deployable app binds these
 * from configuration and hands them to the endpoints.
 *
 * @param authorizationCodeTtl how long an issued authorization code (and a pending request) stays usable
 * @param accessTokenTtl how long an issued access token stays usable — capped, for a brokering provider, by
 *     the life of the credential sealed inside it
 * @param refreshTokenTtl how long an issued refresh token stays usable; with no revocation, its expiry is
 *     what ends a session
 */
public record AsSettings(
        Duration authorizationCodeTtl,
        Duration accessTokenTtl,
        Duration refreshTokenTtl
) {
}
