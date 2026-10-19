package de.iter8.oauth.app;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import de.iter8.oauth.app.AuthorizationServerProperties.ProviderConfig;
import de.iter8.oauth.as.AsSettings;
import de.iter8.oauth.as.AuthorizationCodeStore;
import de.iter8.oauth.as.AuthorizationServerUris;
import de.iter8.oauth.as.ConsentStore;
import de.iter8.oauth.as.DiscoveringResourceEncryptionKeyResolver;
import de.iter8.oauth.as.PendingAuthorizationStore;
import de.iter8.oauth.as.ProviderRegistry;
import de.iter8.oauth.as.RefreshTokenLedger;
import de.iter8.oauth.as.TokenCodecs;
import de.iter8.oauth.as.UpstreamProvider;
import de.iter8.oauth.as.provider.BrokeredTokenProvider;
import de.iter8.oauth.as.provider.OidcIdentityProvider;
import de.iter8.oauth.cimd.ClientAssertionVerifier;
import de.iter8.oauth.cimd.ClientIdMetadataResolver;
import de.iter8.oauth.token.IssuedTokenCodec;
import de.iter8.oauth.token.JweTokenCodec;
import de.iter8.oauth.token.JwsTokenCodec;
import de.iter8.oauth.token.RefreshTokenCodec;
import de.iter8.oauth.token.ResourceEncryptionKeyResolver;
import de.iter8.oauth.token.TokenKeys;
import de.iter8.oauth.token.TokenModel;

/**
 * Wires the authorization-server engine from configuration: the stores, the client-onboarding resolver and
 * assertion verifier, the token codecs, and the provider registry the endpoints run against.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfiguration {

    // Boot 4 no longer always auto-provides a WebClient.Builder; supply one when absent.
    @Bean
    @ConditionalOnMissingBean
    WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    @Bean
    AuthorizationServerUris authorizationServerUris(AuthorizationServerProperties props) {
        return new AuthorizationServerUris(props.issuer());
    }

    @Bean
    AsSettings asSettings(AuthorizationServerProperties props) {
        return new AsSettings(props.authorizationCodeTtl(), props.accessTokenTtl(),
                props.refreshTokenTtl(), props.consentTtl(), props.trustedClients());
    }

    @Bean
    ClientIdMetadataResolver clientIdMetadataResolver(AuthorizationServerProperties props,
            WebClient.Builder webClientBuilder) {
        return new ClientIdMetadataResolver(webClientBuilder, props.clientMetadataCacheTtl(),
                props.allowLoopbackClients());
    }

    @Bean
    ClientAssertionVerifier clientAssertionVerifier(ClientIdMetadataResolver resolver,
            AuthorizationServerProperties props) {
        return new ClientAssertionVerifier(resolver, props.clientMetadataCacheTtl());
    }

    @Bean
    PendingAuthorizationStore pendingAuthorizationStore() {
        return new PendingAuthorizationStore();
    }

    @Bean
    ConsentStore consentStore(AuthorizationServerProperties props) {
        return new ConsentStore(props.consentTtl());
    }

    @Bean
    RefreshTokenLedger refreshTokenLedger(AuthorizationServerProperties props) {
        return new RefreshTokenLedger(props.refreshTokenTtl());
    }

    @Bean
    AuthorizationCodeStore authorizationCodeStore() {
        return new AuthorizationCodeStore();
    }

    @Bean
    RefreshTokenCodec refreshTokenCodec(AuthorizationServerProperties props) {
        return new RefreshTokenCodec(props.keys().refreshTokenKey(), issuer(props));
    }

    @Bean
    ProviderRegistry providerRegistry(AuthorizationServerProperties props,
            WebClient.Builder webClientBuilder) {
        List<UpstreamProvider> providers = new ArrayList<>();
        props.providers().forEach((id, config) -> providers.add(build(id, config, webClientBuilder)));
        log.info("Configured {} upstream provider(s): {}", providers.size(),
                providers.stream().map(UpstreamProvider::id).toList());
        return new ProviderRegistry(providers, props.resources(), props.defaultProvider());
    }

    @Bean
    TokenCodecs tokenCodecs(AuthorizationServerProperties props, ProviderRegistry registry,
            ResourceEncryptionKeyResolver sealingKeyResolver) {
        String issuer = issuer(props);

        JwsTokenCodec jws = null;
        if (registry.hasSignedIdentityProvider()) {
            TokenKeys keys = new TokenKeys(props.keys().jwsPublicKey(), props.keys().jwsPrivateKey());
            if (keys.publicKey() == null || keys.privateKey() == null) {
                throw new IllegalStateException("An identity provider is configured, so JWS signing needs "
                        + "both halves of an RSA keypair. Set iter8.oauth.keys.jws-public-key and "
                        + "jws-private-key, or neither (a throwaway pair is generated when both are absent).");
            }
            jws = new JwsTokenCodec(keys.publicKey(), keys.privateKey(), issuer);
        }

        IssuedTokenCodec jwe = null;
        boolean needJwe = registry.all().stream()
                .anyMatch(provider -> provider.tokenModel() == TokenModel.SEALED_CREDENTIAL);
        if (needJwe) {
            jwe = new JweTokenCodec(sealingKeyResolver, null, issuer);
        }

        return new TokenCodecs(jwe, jws);
    }

    /**
     * The AS side of the SEALED_CREDENTIAL key model: each brokered resource is sealed to its own key,
     * discovered from that resource's RFC 9728 metadata and cached. There is no static key — a resource that
     * publishes none cannot be sealed to, and issuance fails closed for it. Exposed as a bean so it can be
     * pre-warmed at startup (see {@link #warmResourceEncryptionKeys}).
     */
    @Bean
    ResourceEncryptionKeyResolver sealingKeyResolver(AuthorizationServerProperties props,
            WebClient.Builder webClientBuilder) {
        if (props.resources().isEmpty()) {
            log.warn("No resources are mapped under iter8.oauth.resources, so no brokered credential can be "
                    + "sealed to a resource's published key.");
        }
        return DiscoveringResourceEncryptionKeyResolver.over(webClientBuilder.build(),
                props.resources().keySet(), issuer(props), props.resourceKeyCacheTtl(), Clock.systemUTC());
    }

    /**
     * Pre-warms the discovery cache at startup for the brokered (SEALED_CREDENTIAL) resources, so a cold
     * instance's first seal finds the key already cached instead of the empty result the non-blocking
     * resolver returns mid-request (issuance is synchronous and runs on a reactor thread, so it cannot wait
     * on the fetch itself). Identity resources publish no encryption key, so they are skipped.
     */
    @Bean
    ApplicationRunner warmResourceEncryptionKeys(AuthorizationServerProperties props,
            ProviderRegistry registry, ResourceEncryptionKeyResolver sealingKeyResolver) {
        return args -> {
            if (!(sealingKeyResolver instanceof DiscoveringResourceEncryptionKeyResolver discovering)) {
                return;
            }
            List<String> brokered = props.resources().entrySet().stream()
                    .filter(entry -> {
                        UpstreamProvider provider = registry.byId(entry.getValue());
                        return provider != null && provider.tokenModel() == TokenModel.SEALED_CREDENTIAL;
                    })
                    .map(Map.Entry::getKey)
                    .toList();
            if (!brokered.isEmpty()) {
                discovering.warm(brokered);
            }
        };
    }

    private UpstreamProvider build(String id, ProviderConfig config, WebClient.Builder webClientBuilder) {
        if (config.type() == null) {
            throw new IllegalStateException("Provider '" + id + "' has no type. Set iter8.oauth.providers."
                    + id + ".type to 'oauth2-broker' or 'oidc-identity'.");
        }
        return switch (config.type()) {
            case "oauth2-broker" -> new BrokeredTokenProvider(id, new BrokeredTokenProvider.Config(config.clientId(),
                    config.clientSecret(), config.authorizationUri(), config.tokenUri(), config.scopes(),
                    config.scopesSupported()), webClientBuilder);
            case "oidc-identity" -> new OidcIdentityProvider(id, new OidcIdentityProvider.Config(config.clientId(),
                    config.clientSecret(), config.authorizationUri(), config.tokenUri(), config.jwksUri(),
                    config.acceptedIssuers(), config.requestedScope(), config.allowedHostedDomains(),
                    config.allowedEmails(), config.scopesSupported()), webClientBuilder);
            default -> throw new IllegalStateException("Provider '" + id + "' has unknown type '"
                    + config.type() + "'. Supported: oauth2-broker, oidc-identity.");
        };
    }

    private static String issuer(AuthorizationServerProperties props) {
        return new AuthorizationServerUris(props.issuer()).issuer();
    }
}
