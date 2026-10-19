package de.iter8.oauth.token;

import java.time.Instant;
import java.util.Map;

/**
 * Seals and opens this server's access tokens. Two implementations, chosen by {@link TokenModel}: a
 * JWE codec that encrypts an upstream credential inside the token, and a JWS codec that signs verified
 * identity claims and is validated by resource servers against this server's JWKS.
 */
public interface IssuedTokenCodec {

    /**
     * @return which token model this codec implements
     */
    TokenModel model();

    /**
     * @param clientId the client the token is issued to
     * @param providerId the upstream provider it stands for
     * @param subject the stable user identity
     * @param scope the scopes granted, or {@code null}
     * @param resource the resource the token is for, which becomes its audience, or {@code null}
     * @param carriedCredential the upstream credential to seal (SEALED_CREDENTIAL), or {@code null}
     * @param identityClaims verified identity claims to carry (SIGNED_IDENTITY), or {@code null}
     * @param expiresAt when the token stops being accepted
     * @return the access token value
     */
    String encode(String clientId, String providerId, String subject, String scope, String resource,
            String carriedCredential, Map<String, Object> identityClaims, Instant expiresAt);

    /**
     * @param value an access token presented by a client
     * @return what it carries
     * @throws InvalidTokenException when it cannot be opened, is of the wrong kind, or has expired
     */
    IssuedToken decode(String value);
}
