package de.iter8.oauth.as;

import java.time.Instant;
import java.util.Map;

/**
 * The outcome of a successful upstream authorization, in a shape that covers both token models.
 *
 * <p>A brokering provider (Oura) fills in {@link #accessCredential}/{@link #refreshCredential} — the upstream
 * tokens to seal — and leaves {@link #identityClaims} empty. An identity provider (Google OIDC) fills in
 * {@link #identityClaims} (e.g. {@code email}, {@code hd}) and leaves the credentials null. {@link #subject}
 * is the stable user identity either way: an account-scoped id for a broker, the verified email for identity.
 *
 * @param subject the stable user identity this authorization is for
 * @param scope the granted scope, in this authorization server's own vocabulary, or {@code null}
 * @param accessCredential the upstream access token to seal (SEALED_CREDENTIAL), or {@code null}
 * @param refreshCredential the upstream refresh token to seal (SEALED_CREDENTIAL), or {@code null}
 * @param credentialExpiresAt when {@link #accessCredential} expires, or {@code null}
 * @param identityClaims identity claims to carry (SIGNED_IDENTITY), never {@code null} (may be empty)
 */
public record UpstreamResult(
        String subject,
        String scope,
        String accessCredential,
        String refreshCredential,
        Instant credentialExpiresAt,
        Map<String, Object> identityClaims
) {

    public UpstreamResult {
        identityClaims = (identityClaims == null) ? Map.of() : Map.copyOf(identityClaims);
    }

    /**
     * A brokered result carrying an upstream credential to seal.
     */
    public static UpstreamResult credential(String subject, String scope, String accessCredential,
            String refreshCredential, Instant credentialExpiresAt) {
        return new UpstreamResult(subject, scope, accessCredential, refreshCredential, credentialExpiresAt,
                Map.of());
    }

    /**
     * An identity result carrying only verified claims about the user.
     */
    public static UpstreamResult identity(String subject, String scope, Map<String, Object> identityClaims) {
        return new UpstreamResult(subject, scope, null, null, null, identityClaims);
    }
}
