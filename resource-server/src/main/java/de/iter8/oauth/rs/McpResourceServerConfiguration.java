package de.iter8.oauth.rs;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;

import com.nimbusds.jose.jwk.JWK;

import de.iter8.oauth.as.EncryptionJwks;
import de.iter8.oauth.as.JweTokenCodec;
import de.iter8.oauth.as.KeyedSealingKeyStore;
import de.iter8.oauth.as.SealingKeyStore;
import de.iter8.oauth.as.SingleKeySealingKeyStore;
import de.iter8.oauth.as.TokenKeys;

/**
 * Inbound security for an MCP server's endpoints, enabled by {@code iter8.resource-server.enabled}.
 *
 * <p>The protected path is an OAuth 2.0 protected resource. Tokens are validated either as signed identity
 * JWTs against the AS JWKS (JWS) or as self-issued sealed tokens opened with this server's private key
 * (JWE). An unauthenticated request gets a {@code WWW-Authenticate} challenge pointing at the protected
 * resource metadata; the well-known and health paths stay public because a client must read them before it
 * has a token.
 *
 * <p>CSRF is off: MCP is machine-to-machine JSON-RPC authenticated by a bearer token, not a cookie, so there
 * is no ambient credential for a cross-site request to ride on.
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class McpResourceServerConfiguration {

    private static final String[] PUBLIC_PATHS = {
            "/.well-known/**",
            "/actuator/health",
            "/actuator/health/**",
    };

    /**
     * Open chain, used when inbound authorization is disabled. Because Spring Security is on the classpath
     * (the resource-server library pulls it), an app that configured no chain would otherwise inherit Boot's
     * default, which locks every endpoint behind generated Basic auth. This keeps everything open until the
     * MCP server is deliberately protected.
     */
    @Bean
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "false",
            matchIfMissing = true)
    SecurityWebFilterChain openMcpSecurity(ServerHttpSecurity http) {
        log.info("MCP inbound authorization is disabled; every request is accepted. Set "
                + "iter8.resource-server.enabled=true before exposing this server beyond localhost.");
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll());
        return http.build();
    }

    @Bean
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "true")
    SecurityWebFilterChain mcpSecurityWebFilterChain(ServerHttpSecurity http,
            McpResourceServerProperties properties) {

        McpBearerTokenEntryPoint entryPoint = new McpBearerTokenEntryPoint(
                resourceMetadataUrl(properties), properties.resourceName());

        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        http.authorizeExchange(exchanges -> exchanges
                        .pathMatchers(PUBLIC_PATHS).permitAll()
                        .pathMatchers(properties.protectedPathPattern())
                        .access(requireScopes(properties.requiredScopes()))
                        .anyExchange().permitAll())
                .oauth2ResourceServer(resourceServer -> {
                    resourceServer.authenticationEntryPoint(entryPoint);
                    switch (properties.tokenValidation()) {
                        case JWS -> resourceServer.jwt(Customizer.withDefaults());
                        case JWE -> resourceServer.opaqueToken(Customizer.withDefaults());
                    }
                })
                .exceptionHandling(handling -> handling.authenticationEntryPoint(entryPoint));
        return http.build();
    }

    /**
     * The JWT decoder for JWS (identity) tokens, with a mandatory audience check: RFC 8707 audience
     * restriction is what keeps a token issued for another resource from being replayed here.
     */
    @Bean
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "true")
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "token-validation", havingValue = "jws",
            matchIfMissing = true)
    ReactiveJwtDecoder mcpJwtDecoder(McpResourceServerProperties properties) {
        String issuer = properties.issuerUri();
        String jwkSetUri = properties.effectiveJwkSetUri();
        if (jwkSetUri == null) {
            throw new IllegalStateException("iter8.resource-server is enabled with JWS validation but no "
                    + "authorization-servers issuer or jwk-set-uri is set; tokens cannot be validated.");
        }

        // Always the JWK set URI (issuer + /.well-known/jwks.json by default): it is lazy — fetched on the
        // first token, not at startup — and the AS publishes JWKS there, not an OIDC discovery document.
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();

        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add((issuer != null) ? JwtValidators.createDefaultWithIssuer(issuer)
                : JwtValidators.createDefault());
        List<String> audiences = properties.audiences();
        if (audiences.isEmpty()) {
            log.warn("No audience is configured for inbound MCP tokens. Set iter8.resource-server.resource so "
                    + "that tokens issued for other resources are rejected.");
        }
        audiences.forEach(audience -> validators.add(new JwtAudienceValidator(audience)));

        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(validators));
        return decoder;
    }

    /**
     * This server's sealing keys: the private halves that open JWE access tokens, and the public halves it
     * publishes for the authorization server to seal to (see {@link ResourceEncryptionJwksController}).
     */
    @Bean
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "true")
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "token-validation", havingValue = "jwe")
    SealingKeyStore sealingKeyStore(McpResourceServerProperties properties) {
        return buildSealingKeyStore(properties);
    }

    /**
     * The introspector for self-issued JWE tokens, opened with the private key the token's {@code kid} names.
     */
    @Bean
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "true")
    @ConditionalOnProperty(prefix = "iter8.resource-server", name = "token-validation", havingValue = "jwe")
    ReactiveOpaqueTokenIntrospector selfIssuedTokenIntrospector(McpResourceServerProperties properties,
            SealingKeyStore sealingKeyStore) {
        String issuer = properties.issuerUri();
        if (issuer == null) {
            throw new IllegalStateException("iter8.resource-server.token-validation is jwe but no "
                    + "authorization-servers issuer is set; the issuer is checked on every token.");
        }
        JweTokenCodec codec = new JweTokenCodec(null, sealingKeyStore, issuer);
        return new SelfIssuedTokenIntrospector(codec, properties.resource());
    }

    /**
     * Builds the sealing key store from configuration: the keyed set when {@code encryption-keys} is given
     * (the rotation-ready form), otherwise the single {@code access-token-private-key}. Fails closed when JWE
     * validation is on but no key is configured.
     */
    private static SealingKeyStore buildSealingKeyStore(McpResourceServerProperties properties) {
        if (!properties.encryptionKeys().isEmpty()) {
            List<JWK> keys = new ArrayList<>();
            for (McpResourceServerProperties.EncryptionKey configured : properties.encryptionKeys()) {
                if (configured.privateKey() == null || configured.privateKey().isBlank()) {
                    throw new IllegalStateException("iter8.resource-server.encryption-keys entry '"
                            + configured.kid() + "' has no private-key.");
                }
                TokenKeys parsed = new TokenKeys(configured.publicKey(), configured.privateKey());
                keys.add(EncryptionJwks.rsaEncryptionKey(parsed.publicKey(), parsed.privateKey(),
                        configured.kid()));
            }
            return new KeyedSealingKeyStore(keys);
        }
        if (properties.accessTokenPrivateKey() != null) {
            TokenKeys parsed = new TokenKeys(null, properties.accessTokenPrivateKey());
            return SingleKeySealingKeyStore.ofRsa(parsed.publicKey(), parsed.privateKey());
        }
        throw new IllegalStateException("iter8.resource-server.token-validation is jwe, which opens sealed "
                + "tokens, but no encryption key is configured. Set iter8.resource-server.encryption-keys[0]."
                + "private-key (or the single access-token-private-key).");
    }

    private static ReactiveAuthorizationManager<AuthorizationContext> requireScopes(List<String> scopes) {
        Set<String> required = scopes.stream()
                .map(scope -> scope.startsWith("SCOPE_") ? scope : "SCOPE_" + scope)
                .collect(Collectors.toUnmodifiableSet());
        return (authentication, context) -> authentication
                .<AuthorizationResult>map(auth -> {
                    Set<String> granted = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toSet());
                    boolean allowed = auth.isAuthenticated() && granted.containsAll(required);
                    if (!allowed && !required.isEmpty()) {
                        log.warn("Refusing an MCP request: required scopes {} are not all present in the "
                                + "token's authorities {}.", required, granted);
                    }
                    return new AuthorizationDecision(allowed);
                })
                .defaultIfEmpty(new AuthorizationDecision(false));
    }

    private static String resourceMetadataUrl(McpResourceServerProperties properties) {
        String resource = properties.resource();
        if (resource == null) {
            return McpResourceServerProperties.METADATA_PATH;
        }
        URI uri = URI.create(resource);
        String path = (uri.getPath() == null || uri.getPath().equals("/")) ? "" : uri.getPath();
        return uri.getScheme() + "://" + uri.getAuthority() + McpResourceServerProperties.METADATA_PATH
                + path;
    }
}
