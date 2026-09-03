package de.iter8.oauth.as;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import de.iter8.oauth.cimd.ClientAssertionException;
import de.iter8.oauth.cimd.ClientAssertionVerifier;
import de.iter8.oauth.cimd.ClientIdMetadata;
import de.iter8.oauth.cimd.ClientIdMetadataResolver;

/**
 * The token endpoint, where an authorization code becomes an access token and a refresh token becomes a
 * fresh pair.
 *
 * <p>No client holds a secret, because no registration takes place for one to have been agreed during. A
 * client is either public (PKCE alone ties the request to the one that began the flow) or authenticates with
 * private_key_jwt against keys its own metadata document publishes. Neither issued token is kept: each
 * carries its own contents, so a refresh consists of opening the presented token, asking the provider for a
 * fresh result, and sealing it into a new pair.
 */
@RequiredArgsConstructor
@Slf4j
@RestController
public class TokenEndpoint {

    private final ProviderRegistry providers;

    private final AuthorizationCodeStore authorizationCodes;

    private final TokenCodecs codecs;

    private final RefreshTokenCodec refreshTokens;

    private final ClientIdMetadataResolver clients;

    private final ClientAssertionVerifier assertions;

    private final AuthorizationServerUris uris;

    private final AsSettings settings;

    @PostMapping(path = AsPaths.TOKEN_PATH,
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<Map<String, Object>>> token(ServerWebExchange exchange) {
        return exchange.getFormData().flatMap(form -> {
            String grantType = form.getFirst("grant_type");
            if ("authorization_code".equals(grantType)) {
                return redeemCode(form, exchange);
            }
            if ("refresh_token".equals(grantType)) {
                return refresh(form, exchange);
            }
            return Mono.just(error(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                    "Supported grants are authorization_code and refresh_token."));
        });
    }

    private Mono<ResponseEntity<Map<String, Object>>> redeemCode(MultiValueMap<String, String> form,
            ServerWebExchange exchange) {
        String code = form.getFirst("code");
        String clientId = form.getFirst("client_id");

        IssuedAuthorizationCode issued = this.authorizationCodes.redeem(code).orElse(null);
        if (issued == null) {
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The authorization code is unknown, already used or expired."));
        }
        if (!issued.clientId().equals(clientId)) {
            log.warn("A token request presented a code issued to '{}' as client '{}'.",
                    issued.clientId(), clientId);
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The authorization code was not issued to this client."));
        }
        if (!issued.redirectUri().equals(form.getFirst("redirect_uri"))) {
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The redirect_uri does not match the one the code was issued against."));
        }
        if (!PkceVerifier.matches(form.getFirst("code_verifier"), issued.codeChallenge())) {
            log.warn("A token request for client '{}' failed PKCE verification.", clientId);
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The code_verifier does not match the code_challenge."));
        }
        UpstreamProvider provider = this.providers.byId(issued.providerId());
        if (provider == null) {
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The provider for this authorization is no longer available."));
        }
        return authenticate(issued.clientId(), issued.tokenEndpointAuthMethod(), form, exchange)
                .then(Mono.fromSupplier(() -> {
                    log.info("Issuing tokens to '{}'.", issued.clientId());
                    return issue(provider, issued.clientId(), issued.scope(), issued.resource(),
                            issued.upstreamResult());
                }))
                .onErrorResume(ClientAssertionException.class, failure -> {
                    log.warn("Refused a token request for '{}': {}", issued.clientId(),
                            failure.getMessage());
                    return Mono.just(error(HttpStatus.UNAUTHORIZED, "invalid_client",
                            failure.getMessage()));
                });
    }

    private Mono<ResponseEntity<Map<String, Object>>> refresh(MultiValueMap<String, String> form,
            ServerWebExchange exchange) {
        IssuedToken presented;
        try {
            presented = this.refreshTokens.decode(form.getFirst("refresh_token"));
        }
        catch (InvalidTokenException failure) {
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant", failure.getMessage()));
        }
        String clientId = form.getFirst("client_id");
        if (clientId != null && !presented.clientId().equals(clientId)) {
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The refresh token was not issued to this client."));
        }
        UpstreamProvider provider = this.providers.byId(presented.providerId());
        if (provider == null) {
            return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                    "The provider for this authorization is no longer available."));
        }
        UpstreamResult prior = rebuild(provider, presented);
        return authenticateFromDocument(presented.clientId(), form, exchange)
                .then(provider.refresh(prior))
                .map(result -> {
                    log.info("Refreshed tokens for '{}'.", presented.clientId());
                    return issue(provider, presented.clientId(), presented.scope(), presented.resource(),
                            result);
                })
                .onErrorResume(ClientAssertionException.class, failure -> {
                    log.warn("Refused a refresh for '{}': {}", presented.clientId(), failure.getMessage());
                    return Mono.just(error(HttpStatus.UNAUTHORIZED, "invalid_client", failure.getMessage()));
                })
                .onErrorResume(failure -> {
                    log.warn("Provider '{}' would not refresh for '{}': {}", provider.id(),
                            presented.clientId(), failure.getMessage());
                    return Mono.just(error(HttpStatus.BAD_REQUEST, "invalid_grant",
                            "The provider would not renew this authorization; the user must authorize "
                                    + "again."));
                });
    }

    /** Reconstructs the upstream material a refresh needs, from the presented refresh token. */
    private UpstreamResult rebuild(UpstreamProvider provider, IssuedToken presented) {
        return switch (provider.tokenModel()) {
            case SEALED_CREDENTIAL -> UpstreamResult.credential(presented.subject(), presented.scope(),
                    null, presented.carriedCredential(), null);
            case SIGNED_IDENTITY -> UpstreamResult.identity(presented.subject(), presented.scope(),
                    presented.identityClaims());
        };
    }

    private Mono<Void> authenticate(String clientId, String tokenEndpointAuthMethod,
            MultiValueMap<String, String> form, ServerWebExchange exchange) {
        if (!ClientIdMetadata.PRIVATE_KEY_JWT.equals(tokenEndpointAuthMethod)) {
            return Mono.empty();
        }
        return this.clients.resolve(clientId).flatMap(client -> authenticate(client, form, exchange));
    }

    private Mono<Void> authenticateFromDocument(String clientId, MultiValueMap<String, String> form,
            ServerWebExchange exchange) {
        return this.clients.resolve(clientId).flatMap(client -> client.usesPrivateKeyJwt()
                ? authenticate(client, form, exchange)
                : Mono.empty());
    }

    private Mono<Void> authenticate(ClientIdMetadata client, MultiValueMap<String, String> form,
            ServerWebExchange exchange) {
        String assertion = form.getFirst("client_assertion");
        if (assertion != null && !assertion.isBlank()) {
            return this.assertions.verify(client, form.getFirst("client_assertion_type"), assertion,
                    audiences(exchange));
        }
        if (client.allowsPublicRedemption()) {
            log.debug("'{}' declares private_key_jwt but also supports none, and presented no assertion; "
                    + "redeeming as a public client on PKCE alone.", client.clientId());
            return Mono.empty();
        }
        return Mono.error(new ClientAssertionException("This client declares "
                + "token_endpoint_auth_method 'private_key_jwt' and lists no other supported method, so "
                + "client_assertion is required."));
    }

    private Set<String> audiences(ServerWebExchange exchange) {
        return Set.of(this.uris.issuer(exchange), this.uris.absolute(exchange, AsPaths.TOKEN_PATH));
    }

    private ResponseEntity<Map<String, Object>> issue(UpstreamProvider provider, String clientId,
            String scope, String resource, UpstreamResult result) {
        IssuedTokenCodec codec = this.codecs.forModel(provider.tokenModel());

        // A sealed credential caps the access token's life; an identity token lives its full configured TTL.
        Instant accessExpiry = (provider.tokenModel() == TokenModel.SEALED_CREDENTIAL)
                ? earliest(Instant.now().plus(this.settings.accessTokenTtl()), result.credentialExpiresAt())
                : Instant.now().plus(this.settings.accessTokenTtl());

        String accessToken = codec.encode(clientId, provider.id(), result.subject(), scope, resource,
                result.accessCredential(), result.identityClaims(), accessExpiry);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", Math.max(0, Duration.between(Instant.now(), accessExpiry).toSeconds()));

        boolean issueRefresh = result.refreshCredential() != null
                || provider.tokenModel() == TokenModel.SIGNED_IDENTITY;
        if (issueRefresh) {
            body.put("refresh_token", this.refreshTokens.encode(clientId, provider.id(), result.subject(),
                    scope, resource, result.refreshCredential(), result.identityClaims(),
                    Instant.now().plus(this.settings.refreshTokenTtl())));
        }
        if (scope != null) {
            body.put("scope", scope);
        }
        return noStore(HttpStatus.OK).body(body);
    }

    private static Instant earliest(Instant first, Instant second) {
        if (second == null) {
            return first;
        }
        return first.isBefore(second) ? first : second;
    }

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, String error,
            String description) {
        return noStore(status).body(Map.of("error", error, "error_description", description));
    }

    private static ResponseEntity.BodyBuilder noStore(HttpStatus status) {
        return ResponseEntity.status(status)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache");
    }
}
