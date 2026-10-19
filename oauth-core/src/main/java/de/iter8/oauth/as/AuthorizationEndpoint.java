package de.iter8.oauth.as;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import de.iter8.oauth.cimd.ClientIdMetadata;
import de.iter8.oauth.cimd.ClientIdMetadataException;
import de.iter8.oauth.cimd.ClientIdMetadataResolver;

/**
 * The authorization endpoint.
 *
 * <p>A client arrives here having resolved this server from a 401. It identifies itself with a Client ID
 * Metadata Document URL, which is fetched and checked; the resource it asks for selects the upstream
 * provider, and if everything holds the user is sent on to that provider to consent. Their return trip is
 * handled by the callback, which issues the authorization code.
 *
 * <p>The order of validation matters more than it looks. Until the client identifier has been resolved and
 * the redirect URL matched exactly against the document, this server has no idea where the client really
 * lives, so a failure at that stage must be shown to the user rather than redirected. Only once both are
 * known good does the endpoint start reporting errors the way OAuth expects, by redirecting.
 *
 * <p>Before the user is sent upstream, they are asked whether this client may continue (see
 * {@link ConsentPage}), unless the client is configured as trusted. The upstream provider's consent covers
 * this server's app, not the client, so without this step any client could obtain a code for a user who had
 * approved this server before.
 */
@RequiredArgsConstructor
@Slf4j
@RestController
public class AuthorizationEndpoint {

    private final ProviderRegistry providers;

    private final AuthorizationServerUris uris;

    private final ClientIdMetadataResolver clients;

    private final PendingAuthorizationStore pendingAuthorizations;

    private final ConsentStore consents;

    private final AsSettings settings;

    @GetMapping(path = AsPaths.AUTHORIZATION_PATH)
    public Mono<ResponseEntity<String>> authorize(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "response_type", required = false) String responseType,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "scope", required = false) String scope,
            @RequestParam(name = "resource", required = false) String resource,
            ServerWebExchange exchange) {

        UpstreamProvider provider = this.providers.forResource(resource);
        if (provider == null) {
            log.error("No upstream provider is configured for resource '{}', and there is no default.",
                    resource);
            return Mono.just(errorPage(HttpStatus.INTERNAL_SERVER_ERROR, "This server is misconfigured",
                    "No upstream provider is configured to authorize the requested resource."));
        }

        return this.clients.resolve(clientId)
                .map(client -> beginAuthorization(client, provider, redirectUri, responseType,
                        codeChallenge, codeChallengeMethod, state, scope, resource, exchange))
                .onErrorResume(ClientIdMetadataException.class, failure -> {
                    log.warn("Refused an authorization request for client_id '{}': {}", clientId,
                            failure.getMessage());
                    return Mono.just(errorPage(HttpStatus.BAD_REQUEST, "Unknown client",
                            failure.getMessage()));
                });
    }

    private ResponseEntity<String> beginAuthorization(ClientIdMetadata client, UpstreamProvider provider,
            String redirectUri, String responseType, String codeChallenge, String codeChallengeMethod,
            String state, String scope, String resource, ServerWebExchange exchange) {

        // Checked before anything is redirected anywhere, by exact string comparison.
        if (!client.allowsRedirectUri(redirectUri)) {
            log.warn("Refused an authorization request from {}: redirect_uri '{}' is not one of {}.",
                    client.clientId(), redirectUri, client.redirectUris());
            return errorPage(HttpStatus.BAD_REQUEST, "Unregistered redirect URL",
                    "The redirect_uri does not exactly match one declared in the client's metadata "
                            + "document, so this server will not redirect to it.");
        }

        // From here the redirect URL is trusted, so errors go back to the client as OAuth errors.
        if (!"code".equals(responseType)) {
            return redirectError(redirectUri, state, "unsupported_response_type",
                    "Only the authorization code flow is supported.");
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            return redirectError(redirectUri, state, "invalid_request",
                    "PKCE is required: send code_challenge and code_challenge_method=S256.");
        }
        if (!"S256".equals(codeChallengeMethod)) {
            return redirectError(redirectUri, state, "invalid_request",
                    "code_challenge_method must be S256.");
        }
        if (client.usesClientSecret()) {
            return redirectError(redirectUri, state, "invalid_client",
                    "This server issues tokens to public clients and to clients that authenticate with "
                            + "private_key_jwt; the metadata document declares token_endpoint_auth_method '"
                            + client.tokenEndpointAuthMethod() + "', which needs a shared secret that no "
                            + "registration here could have agreed.");
        }
        String unsupportedScope = firstUnsupportedScope(scope, provider);
        if (unsupportedScope != null) {
            return redirectError(redirectUri, state, "invalid_scope",
                    "This server does not issue the scope '" + unsupportedScope + "'.");
        }

        PendingAuthorization authorization = new PendingAuthorization(provider.id(), client.clientId(),
                client.displayName(), redirectUri, state, codeChallenge, client.tokenEndpointAuthMethod(),
                scope, resource, PendingAuthorizationStore.expiryFrom(this.settings.authorizationCodeTtl()));
        try {
            if (this.settings.trusts(client.clientId())) {
                log.info("Authorizing trusted client '{}' ({}) via provider '{}'; sending the user upstream.",
                        client.displayName(), client.clientId(), provider.id());
                return ResponseEntity.status(HttpStatus.FOUND)
                        .location(UpstreamRedirect.start(this.pendingAuthorizations, this.uris, provider,
                                authorization))
                        .build();
            }
            return consentPage(authorization);
        }
        catch (StoreFullException full) {
            log.warn("Refused an authorization request from {}: {}", client.clientId(), full.getMessage());
            return redirectError(redirectUri, state, "temporarily_unavailable",
                    "This server is handling too many authorization requests. Try again shortly.");
        }
    }

    private ResponseEntity<String> consentPage(PendingAuthorization authorization) {
        String binding = PendingAuthorizationStore.randomToken();
        String consentId = this.consents.store(authorization, binding);
        String formAction = this.uris.absolute(AsPaths.CONSENT_PATH);
        log.info("Asking the user whether '{}' ({}) may continue to provider '{}'.",
                authorization.clientName(), authorization.clientId(), authorization.providerId());
        return ResponseEntity.ok()
                .headers(ConsentPage.headers())
                .header(HttpHeaders.SET_COOKIE,
                        ConsentEndpoint.bindingCookie(consentId, binding, formAction, this.consents.ttl()))
                .contentType(MediaType.TEXT_HTML)
                .body(ConsentPage.render(formAction, consentId, authorization));
    }

    private String firstUnsupportedScope(String scope, UpstreamProvider provider) {
        if (scope == null || scope.isBlank()) {
            return null;
        }
        List<String> supported = provider.scopesSupported();
        for (String requested : scope.trim().split("\\s+")) {
            if (!supported.contains(requested)) {
                return requested;
            }
        }
        return null;
    }

    static ResponseEntity<String> redirectError(String redirectUri, String state, String error,
            String description) {
        UriComponentsBuilder location = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", error)
                .queryParam("error_description", description);
        if (state != null) {
            location.queryParam("state", state);
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(location.encode(StandardCharsets.UTF_8).build().toUriString()))
                .build();
    }

    static ResponseEntity<String> errorPage(HttpStatus status, String title, String detail) {
        return ResponseEntity.status(status)
                .contentType(MediaType.TEXT_PLAIN)
                .body(title + "\n\n" + detail + "\n");
    }
}
