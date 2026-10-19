package de.iter8.oauth.token;

import java.time.Instant;
import java.util.Map;

/**
 * What one of this server's tokens carries, once opened.
 *
 * @param clientId the client it was issued to
 * @param providerId the upstream provider it stands for, so a refresh can be routed back
 * @param subject the stable user identity
 * @param scope the scopes granted
 * @param resource the resource it is valid at
 * @param carriedCredential the upstream credential sealed inside (SEALED_CREDENTIAL access/refresh tokens),
 *     or {@code null} for an identity token
 * @param identityClaims verified identity claims (SIGNED_IDENTITY tokens), never {@code null} (may be empty)
 * @param expiresAt when it stops being accepted
 */
public record IssuedToken(
        String clientId,
        String providerId,
        String subject,
        String scope,
        String resource,
        String carriedCredential,
        Map<String, Object> identityClaims,
        Instant expiresAt
) {

    public IssuedToken {
        identityClaims = (identityClaims == null) ? Map.of() : Map.copyOf(identityClaims);
    }
}
