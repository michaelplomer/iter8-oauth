package de.iter8.oauth.as;

/**
 * Resolves this authorization server's own absolute URLs.
 *
 * <p>The issuer is the identity everything else is written against: it appears in the metadata document, it
 * is what a client checks the metadata against, and it prefixes every endpoint advertised. It must be
 * configured. Deriving it from the request would let whoever controls the request's Host or forwarded headers
 * choose the issuer, and behind a TLS-terminating proxy it would come out as {@code http://}.
 */
public final class AuthorizationServerUris {

    private final String issuer;

    /**
     * @param issuer this server's issuer identifier, its public URL
     * @throws IllegalStateException when the issuer is missing or blank
     */
    public AuthorizationServerUris(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("iter8.oauth.issuer is not set. Set it to this server's public "
                    + "URL, for example https://auth.example.com.");
        }
        this.issuer = stripTrailingSlash(issuer);
    }

    /**
     * @return this server's issuer identifier, without a trailing slash
     */
    public String issuer() {
        return this.issuer;
    }

    /**
     * @param path a path beginning with a slash
     * @return the absolute URL of that path on this server
     */
    public String absolute(String path) {
        return this.issuer + path;
    }

    private static String stripTrailingSlash(String value) {
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
