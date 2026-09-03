package de.iter8.oauth.as;

import java.net.URI;

import org.springframework.web.server.ServerWebExchange;

/**
 * Resolves this authorization server's own absolute URLs.
 *
 * <p>The issuer is the identity everything else is written against: it appears in the metadata document, it
 * is what a client checks the metadata against, and it prefixes every endpoint advertised. Deriving it from
 * the request is convenient and fragile in the same breath — behind a TLS-terminating proxy the request
 * arrives as plain HTTP, so an unconfigured issuer comes out as {@code http://} and every client rejects it.
 * Configuring the issuer explicitly is the way to be certain.
 */
public final class AuthorizationServerUris {

    private final String configuredIssuer;

    /**
     * @param configuredIssuer this server's issuer identifier, or {@code null}/blank to derive it per request
     */
    public AuthorizationServerUris(String configuredIssuer) {
        this.configuredIssuer = configuredIssuer;
    }

    /**
     * @param exchange the current exchange, used only when no issuer is configured
     * @return this server's issuer identifier, without a trailing slash
     */
    public String issuer(ServerWebExchange exchange) {
        if (this.configuredIssuer != null && !this.configuredIssuer.isBlank()) {
            return stripTrailingSlash(this.configuredIssuer);
        }
        URI uri = exchange.getRequest().getURI();
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    /**
     * @param exchange the current exchange
     * @param path a path beginning with a slash
     * @return the absolute URL of that path on this server
     */
    public String absolute(ServerWebExchange exchange, String path) {
        return issuer(exchange) + path;
    }

    private static String stripTrailingSlash(String value) {
        String trimmed = value.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }
}
