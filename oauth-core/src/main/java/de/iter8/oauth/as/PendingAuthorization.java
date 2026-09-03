package de.iter8.oauth.as;

import java.time.Instant;

/**
 * An authorization request that has been validated and is waiting for the user to consent upstream.
 *
 * <p>Everything the eventual authorization code must be bound to is captured here, at the moment it was
 * checked. Re-reading any of it from the callback would mean trusting whatever came back through the
 * browser, and the browser is the least trustworthy part of this flow.
 *
 * @param providerId the upstream provider this request is being sent to
 * @param clientId the Client Identifier URL, already resolved and validated
 * @param clientName the client's display name, for the consent screen and the logs
 * @param redirectUri the client's redirect URL, already matched exactly against its metadata document
 * @param clientState the client's {@code state}, echoed back untouched
 * @param codeChallenge the client's PKCE challenge, verified at the token endpoint
 * @param tokenEndpointAuthMethod how the client said it will authenticate when it redeems the code
 * @param scope the scopes requested
 * @param resource the resource indicator the client asked for, or {@code null}
 * @param expiresAt when this pending request stops being usable
 */
public record PendingAuthorization(
        String providerId,
        String clientId,
        String clientName,
        String redirectUri,
        String clientState,
        String codeChallenge,
        String tokenEndpointAuthMethod,
        String scope,
        String resource,
        Instant expiresAt
) {

    /**
     * @return whether this request has outlived its window
     */
    public boolean isExpired() {
        return Instant.now().isAfter(this.expiresAt);
    }
}
