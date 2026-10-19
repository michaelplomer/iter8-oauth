package de.iter8.oauth.token;

import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;

/**
 * Authorization-server side of the SEALED_CREDENTIAL key model: resolves the public key a credential must be
 * encrypted to, <em>per resource</em> (the token's audience).
 *
 * <p>The inverse of the JWS/JWKS flow. There the AS holds the private key and publishes its public half; here
 * the resource server holds the private key and publishes <em>its</em> public half, and this resolver is how
 * the AS finds it — typically by discovering the resource's RFC 9728 metadata, reading its {@code jwks_uri},
 * and selecting the encryption key ({@code use:"enc"}). Sealing to that key is what makes a token openable by
 * exactly one audience.
 */
public interface ResourceEncryptionKeyResolver {

    /**
     * @param resource the canonical resource identifier the token is for (its audience)
     * @return the current public encryption key to seal to (a JWK with {@code use:"enc"}, a {@code kid}, and
     *     an {@code alg}), or empty when none is available for this resource — the caller then falls back to a
     *     statically configured key or fails closed rather than sealing to an unknown party
     */
    Optional<JWK> encryptionKeyFor(String resource);
}
