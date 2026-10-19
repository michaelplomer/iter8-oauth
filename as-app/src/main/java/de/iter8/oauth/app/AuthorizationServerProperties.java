package de.iter8.oauth.app;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Everything the authorization server is configured with, under {@code iter8.oauth}. The providers and their
 * resource mapping are declarative: adding a backing provider is a config entry, not code.
 *
 * @param issuer this server's issuer identifier, its public URL, stamped into every token; required
 * @param authorizationCodeTtl how long an issued authorization code (and a pending request) stays usable
 * @param accessTokenTtl how long an issued access token stays usable
 * @param refreshTokenTtl how long an issued refresh token stays usable
 * @param clientMetadataCacheTtl how long a fetched Client ID Metadata Document is reused
 * @param resourceKeyCacheTtl how long a discovered resource encryption key is reused before a background
 *     refresh (SEALED_CREDENTIAL model)
 * @param allowLoopbackClients whether a client identifier may point at loopback (development only)
 * @param consentTtl how long the user has to answer the consent page
 * @param trustedClients client identifiers that skip the consent page, compared exactly; every other client
 *     is shown to the user for approval before the user is sent upstream
 * @param keys the key material for the token codecs
 * @param providers the upstream providers, keyed by the id used in tokens and callbacks
 * @param resources canonical-resource to provider-id, choosing which provider authorizes each resource
 * @param defaultProvider the provider used when a request names no mapped resource
 */
@ConfigurationProperties("iter8.oauth")
public record AuthorizationServerProperties(
        String issuer,
        @DefaultValue("60s") Duration authorizationCodeTtl,
        @DefaultValue("1h") Duration accessTokenTtl,
        @DefaultValue("30d") Duration refreshTokenTtl,
        @DefaultValue("15m") Duration clientMetadataCacheTtl,
        @DefaultValue("15m") Duration resourceKeyCacheTtl,
        @DefaultValue("false") boolean allowLoopbackClients,
        @DefaultValue("10m") Duration consentTtl,
        @DefaultValue List<String> trustedClients,
        @DefaultValue Keys keys,
        Map<String, ProviderConfig> providers,
        Map<String, String> resources,
        String defaultProvider
) {

    public AuthorizationServerProperties {
        issuer = blankToNull(issuer);
        providers = (providers == null) ? Map.of() : providers;
        resources = (resources == null) ? Map.of() : resources;
        defaultProvider = blankToNull(defaultProvider);
    }

    /**
     * Token key material. Each half is optional: absent halves are generated for the run (development), and
     * a split deployment configures only the half it holds. No SEALED_CREDENTIAL key lives here — those keys
     * belong to the resource servers, and the authorization server discovers each resource's public key from
     * its RFC 9728 metadata.
     *
     * @param jwsPublicKey the SIGNED_IDENTITY signing key's public half (base64 X.509 or PEM)
     * @param jwsPrivateKey the SIGNED_IDENTITY signing key's private half (base64 PKCS#8 or PEM)
     * @param refreshTokenKey base64 of the 32 byte symmetric key that seals refresh tokens
     */
    public record Keys(
            String jwsPublicKey,
            String jwsPrivateKey,
            String refreshTokenKey
    ) {
        public Keys {
            jwsPublicKey = blankToNull(jwsPublicKey);
            jwsPrivateKey = blankToNull(jwsPrivateKey);
            refreshTokenKey = blankToNull(refreshTokenKey);
        }
    }

    /**
     * One provider's configuration. {@code type} selects the implementation; the remaining fields are the
     * union of what the implementations need, and unused ones are ignored.
     *
     * @param type "oauth2-broker" or "oidc-identity"
     * @param clientId this server's client id at the provider
     * @param clientSecret this server's client secret at the provider
     * @param authorizationUri the provider's authorization endpoint
     * @param tokenUri the provider's token endpoint
     * @param scopes upstream scopes to request (broker)
     * @param scopesSupported scopes this server advertises for this provider
     * @param jwksUri the provider's JWKS (identity)
     * @param acceptedIssuers accepted id_token issuers (identity)
     * @param requestedScope the scope to request (identity), e.g. "openid email"
     * @param allowedHostedDomains Workspace domains admitted wholesale (identity)
     * @param allowedEmails individual accounts admitted (identity)
     */
    public record ProviderConfig(
            String type,
            String clientId,
            String clientSecret,
            String authorizationUri,
            String tokenUri,
            List<String> scopes,
            List<String> scopesSupported,
            String jwksUri,
            List<String> acceptedIssuers,
            String requestedScope,
            List<String> allowedHostedDomains,
            List<String> allowedEmails
    ) {
        public ProviderConfig {
            scopes = (scopes == null) ? List.of() : List.copyOf(scopes);
            scopesSupported = (scopesSupported == null) ? List.of() : List.copyOf(scopesSupported);
            acceptedIssuers = (acceptedIssuers == null) ? List.of() : List.copyOf(acceptedIssuers);
            allowedHostedDomains = (allowedHostedDomains == null) ? List.of()
                    : List.copyOf(allowedHostedDomains);
            allowedEmails = (allowedEmails == null) ? List.of() : List.copyOf(allowedEmails);
        }
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }
}
