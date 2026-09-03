package de.iter8.oauth.as;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * The claim set every token kind shares, and the checks all are held to.
 *
 * <p>Kept in one place because access and refresh tokens are sealed with different keys but must agree on
 * what they mean. A difference between them here would be a difference an attacker could work with.
 *
 * <p>Generalized over both token models: a SEALED_CREDENTIAL token carries the upstream credential in
 * {@code cred}; a SIGNED_IDENTITY token carries verified claims in {@code idt}. Neither is required — that a
 * credential must be present was an artefact of the single brokering provider this engine grew out of.
 */
final class TokenClaims {

    static final String KIND = "token_kind";

    static final String CLIENT_ID = "client_id";

    static final String PROVIDER_ID = "provider_id";

    static final String SCOPE = "scope";

    /** The sealed upstream credential (SEALED_CREDENTIAL tokens). */
    static final String CRED = "cred";

    /** Verified identity claims, nested (SIGNED_IDENTITY tokens). */
    static final String IDT = "idt";

    private TokenClaims() {
    }

    static JWTClaimsSet build(String kind, String issuer, String clientId, String providerId, String subject,
            String scope, String resource, String carriedCredential, Map<String, Object> identityClaims,
            Instant expiresAt) {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject((subject != null && !subject.isBlank()) ? subject : clientId)
                .claim(KIND, kind)
                .claim(CLIENT_ID, clientId)
                .claim(PROVIDER_ID, providerId)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(expiresAt));
        if (scope != null) {
            claims.claim(SCOPE, scope);
        }
        if (resource != null) {
            // The audience is what stops a token minted for one resource being spent at another.
            claims.audience(resource);
        }
        if (carriedCredential != null && !carriedCredential.isBlank()) {
            claims.claim(CRED, carriedCredential);
        }
        if (identityClaims != null && !identityClaims.isEmpty()) {
            claims.claim(IDT, identityClaims);
        }
        return claims.build();
    }

    static IssuedToken verify(JWTClaimsSet claims, String expectedKind, String expectedIssuer) {
        if (!expectedIssuer.equals(claims.getIssuer())) {
            throw new InvalidTokenException("The token was issued by somebody else.");
        }
        if (!expectedKind.equals(claims.getClaim(KIND))) {
            // The keys already keep the two kinds apart, since only the resource server can open an access
            // token. This is the check that still holds if that ever stops being true.
            throw new InvalidTokenException("This is not a " + expectedKind + " token.");
        }
        Date expiry = claims.getExpirationTime();
        if (expiry == null || Instant.now().isAfter(expiry.toInstant())) {
            throw new InvalidTokenException("The token has expired.");
        }
        Map<String, Object> identity;
        try {
            identity = claims.getJSONObjectClaim(IDT);
        }
        catch (java.text.ParseException failure) {
            throw new InvalidTokenException("The token's identity claims are malformed.");
        }
        return new IssuedToken(
                (String) claims.getClaim(CLIENT_ID),
                (String) claims.getClaim(PROVIDER_ID),
                claims.getSubject(),
                (String) claims.getClaim(SCOPE),
                (claims.getAudience() == null || claims.getAudience().isEmpty())
                        ? null : claims.getAudience().get(0),
                (String) claims.getClaim(CRED),
                identity,
                expiry.toInstant());
    }
}
