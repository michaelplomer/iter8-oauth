package de.iter8.oauth.as;

/**
 * The fixed paths this authorization server serves. A single callback path is shared by every upstream
 * provider — the {@code state} that comes back resolves to a pending request that records which provider it
 * belongs to, so no per-provider path is needed and every upstream registers the same redirect URL.
 */
public final class AsPaths {

    private AsPaths() {
    }

    public static final String AUTHORIZATION_PATH = "/oauth2/authorize";

    public static final String TOKEN_PATH = "/oauth2/token";

    public static final String CALLBACK_PATH = "/oauth2/callback";

    /** RFC 8414 authorization server metadata. */
    public static final String METADATA_PATH = "/.well-known/oauth-authorization-server";

    /** Public keys for verifying SIGNED_IDENTITY (JWS) access tokens. */
    public static final String JWKS_PATH = "/.well-known/jwks.json";
}
