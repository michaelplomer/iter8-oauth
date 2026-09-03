package de.iter8.oauth.as;

import java.time.Instant;

/**
 * An authorization code this server issued, and everything the token request must match.
 *
 * @param providerId the upstream provider whose result this code stands for
 * @param clientId the client the code was issued to
 * @param redirectUri the redirect URL it was issued against
 * @param codeChallenge the client's PKCE challenge, checked against the verifier at the token endpoint
 * @param tokenEndpointAuthMethod how the client must authenticate to redeem this code
 * @param scope the scopes granted
 * @param resource the resource indicator requested, or {@code null}
 * @param upstreamResult the upstream authorization this code stands for
 * @param expiresAt when the code stops being redeemable
 */
public record IssuedAuthorizationCode(
        String providerId,
        String clientId,
        String redirectUri,
        String codeChallenge,
        String tokenEndpointAuthMethod,
        String scope,
        String resource,
        UpstreamResult upstreamResult,
        Instant expiresAt
) {

    /**
     * @return whether the code has outlived its window
     */
    public boolean isExpired() {
        return Instant.now().isAfter(this.expiresAt);
    }
}
