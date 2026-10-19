package de.iter8.oauth.rs;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import reactor.core.publisher.Mono;

import de.iter8.oauth.token.InvalidTokenException;
import de.iter8.oauth.token.IssuedToken;
import de.iter8.oauth.token.JweTokenCodec;
import de.iter8.oauth.token.ResourceIdentifiers;

/**
 * Opens a SEALED_CREDENTIAL (JWE) access token the authorization server issued.
 *
 * <p>No lookup and no network call: the token carries its own contents, sealed with a key only this resource
 * server holds, so validating it is decrypting it. The upstream credential comes out with it and is placed on
 * the principal, where an outbound provider finds it; any identity claims are placed there too.
 */
@Slf4j
public class SelfIssuedTokenIntrospector implements ReactiveOpaqueTokenIntrospector {

    /** Attribute under which the sealed upstream credential is carried on the authenticated principal. */
    public static final String CARRIED_CREDENTIAL_ATTRIBUTE = "mcp.carried-credential";

    private final JweTokenCodec codec;

    private final String expectedResource;

    /**
     * @param codec opens the token
     * @param expectedResource this server's canonical resource identifier, which a token must be audienced
     *     to; {@code null} accepts any audience (and warns)
     */
    public SelfIssuedTokenIntrospector(JweTokenCodec codec, String expectedResource) {
        this.codec = codec;
        this.expectedResource = (expectedResource == null || expectedResource.isBlank())
                ? null : expectedResource;
        if (this.expectedResource == null) {
            log.warn("No resource identifier is configured, so access tokens are accepted whatever resource "
                    + "they were issued for. The MCP specification requires a server to check that a token "
                    + "was issued for it; set iter8.resource-server.resource.");
        }
    }

    @Override
    public Mono<OAuth2AuthenticatedPrincipal> introspect(String token) {
        return Mono.fromCallable(() -> this.codec.decode(token))
                .onErrorMap(InvalidTokenException.class, failure -> {
                    log.warn("Refusing an access token: {}", failure.getMessage());
                    return new BadOpaqueTokenException(failure.getMessage());
                })
                .map(this::principal);
    }

    private OAuth2AuthenticatedPrincipal principal(IssuedToken token) {
        if (this.expectedResource != null && token.resource() != null
                && !ResourceIdentifiers.match(this.expectedResource, token.resource())) {
            log.warn("Refusing an access token issued for resource '{}'; this server is '{}'.",
                    token.resource(), this.expectedResource);
            throw new BadOpaqueTokenException("The access token was issued for " + token.resource()
                    + ", not for this server.");
        }

        String name = (token.subject() != null) ? token.subject() : token.clientId();
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("active", true);
        attributes.put("client_id", token.clientId());
        attributes.put("sub", name);
        attributes.put("exp", token.expiresAt());
        if (token.scope() != null) {
            attributes.put("scope", token.scope());
        }
        if (token.resource() != null) {
            attributes.put("aud", List.of(token.resource()));
        }
        if (token.carriedCredential() != null) {
            attributes.put(CARRIED_CREDENTIAL_ATTRIBUTE, token.carriedCredential());
        }
        token.identityClaims().forEach(attributes::putIfAbsent);

        List<GrantedAuthority> authorities = (token.scope() == null) ? List.of()
                : Arrays.stream(token.scope().trim().split("\\s+"))
                        .filter(scope -> !scope.isEmpty())
                        .<GrantedAuthority>map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                        .toList();
        return new DefaultOAuth2AuthenticatedPrincipal(name, attributes, authorities);
    }
}
