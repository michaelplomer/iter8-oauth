package de.iter8.oauth.rs;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Inbound authorization for an MCP server that trusts the iter8-oauth authorization server. The MCP endpoint
 * is an OAuth 2.0 protected resource; clients present access tokens the AS issued.
 *
 * <p>Disabled by default, so a local stdio/loopback run needs no tokens. Turn it on for anything reachable
 * off the machine.
 *
 * @param enabled whether MCP requests must carry a valid access token
 * @param resource this server's canonical resource identifier (RFC 8707); the AS puts it in the token's
 *     audience, which is what stops a token minted for another resource being replayed here
 * @param resourceName a human-readable name for the protected resource metadata document
 * @param authorizationServers issuer identifiers of the authorization server(s) that may issue tokens; the
 *     first is the JWS issuer unless jwkSetUri is set
 * @param jwkSetUri where to fetch signing keys for JWS validation; derived from the issuer when unset
 * @param scopesSupported scopes advertised in the protected resource metadata
 * @param requiredScopes scopes a token must carry to call the MCP endpoint; empty accepts any valid token
 * @param protectedPathPattern the path pattern the token is required on
 * @param tokenValidation how an inbound token is checked: JWS (signed identity) or JWE (self-issued, sealed)
 * @param accessTokenPrivateKey base64 PKCS#8 RSA private key that opens JWE access tokens; the single-key,
 *     pre-rotation form. Prefer {@code encryptionKeys} for anything that must rotate. (JWE mode only.)
 * @param encryptionKeys the sealing keys this server holds and publishes (JWE mode); the first is the current
 *     one advertised for new tokens, the rest are retiring keys kept only to open tokens still in flight.
 *     Supersedes {@code accessTokenPrivateKey} when non-empty.
 */
@ConfigurationProperties("iter8.resource-server")
public record McpResourceServerProperties(
        @DefaultValue("false") boolean enabled,
        String resource,
        @DefaultValue("MCP Server") String resourceName,
        @DefaultValue List<String> authorizationServers,
        String jwkSetUri,
        @DefaultValue List<String> scopesSupported,
        @DefaultValue List<String> requiredScopes,
        @DefaultValue("/mcp/**") String protectedPathPattern,
        @DefaultValue("jws") TokenValidation tokenValidation,
        String accessTokenPrivateKey,
        @DefaultValue List<EncryptionKey> encryptionKeys
) {

    /** How an inbound access token is checked. */
    public enum TokenValidation {

        /** A signed identity JWT, verified against the AS JWKS. The standard path for identity providers. */
        JWS,

        /** A self-issued token sealed by the AS (JWE), opened here with the resource server's private key. */
        JWE
    }

    /**
     * One sealing keypair the resource server publishes and opens tokens with.
     *
     * @param kid the key id, matched against a token's JWE header; derived from the RSA thumbprint when blank
     * @param privateKey base64 PKCS#8 RSA private key (opens tokens sealed to this key)
     * @param publicKey base64 X.509 RSA public key (published for the AS to seal to); derived from a CRT
     *     private key when omitted
     */
    public record EncryptionKey(String kid, String privateKey, String publicKey) {
    }

    public McpResourceServerProperties {
        resource = blankToNull(resource);
        jwkSetUri = blankToNull(jwkSetUri);
        accessTokenPrivateKey = blankToNull(accessTokenPrivateKey);
        encryptionKeys = (encryptionKeys == null) ? List.of() : List.copyOf(encryptionKeys);
    }

    /** Path of the protected resource metadata document, as fixed by RFC 9728. */
    public static final String METADATA_PATH = "/.well-known/oauth-protected-resource";

    /** @return the issuer to validate tokens against, or {@code null} */
    public String issuerUri() {
        return this.authorizationServers.isEmpty() ? null : this.authorizationServers.get(0);
    }

    /** @return the JWK set URI for JWS validation, derived from the issuer when not set explicitly */
    public String effectiveJwkSetUri() {
        if (this.jwkSetUri != null && !this.jwkSetUri.isBlank()) {
            return this.jwkSetUri;
        }
        String issuer = issuerUri();
        if (issuer == null) {
            return null;
        }
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        return base + "/.well-known/jwks.json";
    }

    /** @return the audience values an inbound token must carry, defaulting to the resource */
    public List<String> audiences() {
        return (this.resource == null) ? List.of() : List.of(this.resource);
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }
}
