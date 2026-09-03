package de.iter8.oauth.app;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import de.iter8.oauth.app.AuthorizationServerProperties.ProviderConfig;
import de.iter8.oauth.as.AsSettings;
import de.iter8.oauth.as.AuthorizationCodeStore;
import de.iter8.oauth.as.AuthorizationServerUris;
import de.iter8.oauth.as.DiscoveringResourceEncryptionKeyResolver;
import de.iter8.oauth.as.IssuedTokenCodec;
import de.iter8.oauth.as.JweTokenCodec;
import de.iter8.oauth.as.ResourceEncryptionKeyResolver;
import de.iter8.oauth.as.JwsTokenCodec;
import de.iter8.oauth.as.PendingAuthorizationStore;
import de.iter8.oauth.as.ProviderRegistry;
import de.iter8.oauth.as.RefreshTokenCodec;
import de.iter8.oauth.as.TokenCodecs;
import de.iter8.oauth.as.TokenKeys;
import de.iter8.oauth.as.TokenModel;
import de.iter8.oauth.as.UpstreamProvider;
import de.iter8.oauth.as.provider.OidcIdentityProvider;
import de.iter8.oauth.as.provider.BrokeredTokenProvider;
import de.iter8.oauth.cimd.ClientAssertionVerifier;
import de.iter8.oauth.cimd.ClientIdMetadataResolver;

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
        if (props.issuer() == null) {
            log.warn("iter8.oauth.issuer is not set, so the issuer is derived from each request and stamped "
                    + "blank into tokens. Behind a TLS-terminating proxy this yields an http issuer, which "
                    + "clients reject. Set it explicitly for anything but local use.");
        }
        return new AuthorizationServerUris(props.issuer());
    }

    @Bean
    AsSettings asSettings(AuthorizationServerProperties props) {
        return new AsSettings(props.authorizationCodeTtl(), props.accessTokenTtl(),
                props.refreshTokenTtl());
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
            WebClient.Builder webClientBuilder) {
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
            jwe = new JweTokenCodec(sealingKeyResolver(props, issuer, webClientBuilder), null, issuer);
        }

        return new TokenCodecs(jwe, jws);
    }

    /**
     * The AS side of the SEALED_CREDENTIAL key model: each brokered resource is sealed to its own key,
     * discovered from that resource's RFC 9728 metadata and cached. There is no static key — a resource that
     * publishes none cannot be sealed to, and issuance fails closed for it.
     */
    private ResourceEncryptionKeyResolver sealingKeyResolver(AuthorizationServerProperties props,
            String issuer, WebClient.Builder webClientBuilder) {
        if (props.resources().isEmpty()) {
            log.warn("A brokering provider is configured but no resources are mapped, so there is no resource "
                    + "whose published key a credential could be sealed to. Map the brokered resources under "
                    + "iter8.oauth.resources.");
        }
        return DiscoveringResourceEncryptionKeyResolver.over(webClientBuilder.build(),
                props.resources().keySet(), issuer, props.resourceKeyCacheTtl(), Clock.systemUTC());
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
        return (props.issuer() == null) ? "" : props.issuer();
    }
}
