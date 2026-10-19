package de.iter8.oauth.as;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.iter8.oauth.token.ResourceIdentifiers;
import de.iter8.oauth.token.TokenModel;

/**
 * The upstream providers this server brokers for, and the mapping from a requested resource to the provider
 * that authorizes it.
 *
 * <p>An MCP client asks to authorize for a particular resource (the downstream MCP server it wants to reach);
 * that resource decides which upstream the user is sent to. A whatable resource maps to Google identity, an
 * Oura resource to the Oura broker. When a request names no resource, or one that is not mapped, the default
 * provider is used.
 */
public class ProviderRegistry {

    private final Map<String, UpstreamProvider> byId = new LinkedHashMap<>();

    private final Map<String, String> resourceToProvider = new LinkedHashMap<>();

    private final String defaultProviderId;

    /**
     * @param providers the configured providers
     * @param resourceToProviderId canonical-resource to provider-id (values must name a configured provider)
     * @param defaultProviderId the provider used when a request names no mapped resource
     */
    public ProviderRegistry(Collection<UpstreamProvider> providers,
            Map<String, String> resourceToProviderId, String defaultProviderId) {
        for (UpstreamProvider provider : providers) {
            this.byId.put(provider.id(), provider);
        }
        resourceToProviderId.forEach((resource, providerId) -> {
            require(this.byId.containsKey(providerId),
                    "resource '" + resource + "' maps to unknown provider '" + providerId + "'");
            this.resourceToProvider.put(ResourceIdentifiers.canonical(resource), providerId);
        });
        require(defaultProviderId == null || this.byId.containsKey(defaultProviderId),
                "default provider '" + defaultProviderId + "' is not configured");
        // A single-provider deployment needs no explicit default.
        this.defaultProviderId = (defaultProviderId != null) ? defaultProviderId
                : (providers.size() == 1 ? providers.iterator().next().id() : null);
    }

    /**
     * @param id a provider id
     * @return the provider, or {@code null} when none is registered under it
     */
    public UpstreamProvider byId(String id) {
        return (id == null) ? null : this.byId.get(id);
    }

    /**
     * @param resource the resource indicator from an authorization request, or {@code null}
     * @return the provider that authorizes it, or {@code null} when there is none and no default
     */
    public UpstreamProvider forResource(String resource) {
        String providerId = (resource == null) ? null
                : this.resourceToProvider.get(ResourceIdentifiers.canonical(resource));
        if (providerId == null) {
            providerId = this.defaultProviderId;
        }
        return byId(providerId);
    }

    /**
     * @return every configured provider
     */
    public Collection<UpstreamProvider> all() {
        return this.byId.values();
    }

    /**
     * @return the union of every provider's advertised scopes, for the server metadata
     */
    public List<String> scopesSupported() {
        Set<String> scopes = new LinkedHashSet<>();
        for (UpstreamProvider provider : this.byId.values()) {
            scopes.addAll(provider.scopesSupported());
        }
        return List.copyOf(scopes);
    }

    /**
     * @return whether any configured provider issues SIGNED_IDENTITY tokens, so JWKS is worth publishing
     */
    public boolean hasSignedIdentityProvider() {
        return this.byId.values().stream().anyMatch(p -> p.tokenModel() == TokenModel.SIGNED_IDENTITY);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException("Provider registry misconfigured: " + message);
        }
    }
}
