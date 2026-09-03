package de.iter8.oauth.as;

/**
 * How an issued access token carries what it stands for — the choice that drives which
 * {@link IssuedTokenCodec} an upstream provider uses.
 *
 * <p>This is anchored to the provider's security semantics, not to configuration convenience: a provider
 * that yields a secret the client must never read <em>must</em> use {@link #SEALED_CREDENTIAL}. Selecting a
 * codec merely because a signing key happens to be configured could leak an upstream credential in a
 * client-readable token, so the mapping is provider-declared and validated, never inferred loosely.
 */
public enum TokenModel {

    /**
     * The token carries an upstream credential sealed inside it, so it is <em>encrypted</em> (JWE): the
     * client must not be able to read the credential it stands for. Used by brokering providers such as Oura.
     */
    SEALED_CREDENTIAL,

    /**
     * The token carries only the authenticated user's identity, so it is <em>signed</em> (JWS) and validated
     * by resource servers against this server's JWKS. Nothing secret travels inside. Used by identity
     * providers such as Google OIDC.
     */
    SIGNED_IDENTITY
}
