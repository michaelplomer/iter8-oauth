package de.iter8.oauth.as;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * Where an upstream provider sends the user back once they have consented.
 *
 * <p>This is the hinge of the bridge. The upstream's code is exchanged here, server to server, for a result
 * that never leaves this process; what goes back to the MCP client is an authorization code of this server's
 * own. Everything the code is bound to comes from the pending request validated at {@code /authorize}, not
 * from this request, because the browser is the least trustworthy participant. The pending request also
 * records which provider it belongs to, so a single callback path serves them all.
 */
@RequiredArgsConstructor
@Slf4j
@RestController
public class CallbackEndpoint {

    private final ProviderRegistry providers;

    private final AuthorizationServerUris uris;

    private final PendingAuthorizationStore pendingAuthorizations;

    private final AuthorizationCodeStore authorizationCodes;

    private final AsSettings settings;

    @GetMapping(path = AsPaths.CALLBACK_PATH)
    public Mono<ResponseEntity<String>> callback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            ServerWebExchange exchange) {

        return Mono.justOrEmpty(this.pendingAuthorizations.consume(state))
                .flatMap(pending -> complete(pending, code, error, errorDescription, exchange))
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    log.warn("Discarded a callback with an unknown or expired state.");
                    return errorPage(HttpStatus.BAD_REQUEST, "This authorization has expired",
                            "Start again from your MCP client. Authorizations are short lived, and each "
                                    + "one can be completed only once.");
                }));
    }

    private Mono<ResponseEntity<String>> complete(PendingAuthorization pending, String code, String error,
            String errorDescription, ServerWebExchange exchange) {

        UpstreamProvider provider = this.providers.byId(pending.providerId());
        if (provider == null) {
            log.error("A pending authorization named provider '{}', which is no longer configured.",
                    pending.providerId());
            return Mono.just(redirect(pending.redirectUri(), builder -> builder
                    .queryParam("error", "server_error")
                    .queryParam("error_description", "The upstream provider is no longer available."),
                    pending.clientState()));
        }
        if (error != null && !error.isBlank()) {
            log.info("Provider '{}' declined authorization for '{}': {}", provider.id(),
                    pending.clientName(), error);
            return Mono.just(redirect(pending.redirectUri(), builder -> builder
                    .queryParam("error", "access_denied")
                    .queryParam("error_description",
                            (errorDescription != null) ? errorDescription : "Access was not granted."),
                    pending.clientState()));
        }
        if (code == null || code.isBlank()) {
            return Mono.just(redirect(pending.redirectUri(), builder -> builder
                    .queryParam("error", "server_error")
                    .queryParam("error_description", "The provider returned no authorization code."),
                    pending.clientState()));
        }

        String callbackUri = this.uris.absolute(AsPaths.CALLBACK_PATH);
        return provider.completeCallback(code, callbackUri, pending)
                .map(result -> {
                    IssuedAuthorizationCode issued = new IssuedAuthorizationCode(provider.id(),
                            pending.clientId(), pending.redirectUri(), pending.codeChallenge(),
                            pending.tokenEndpointAuthMethod(), pending.scope(), pending.resource(), result,
                            PendingAuthorizationStore.expiryFrom(this.settings.authorizationCodeTtl()));
                    String value = this.authorizationCodes.store(issued);
                    log.info("Issued an authorization code to '{}'.", pending.clientName());
                    return redirect(pending.redirectUri(),
                            builder -> builder.queryParam("code", value), pending.clientState());
                })
                .onErrorResume(UpstreamAuthorizationException.class, failure -> {
                    log.info("Provider '{}' authenticated but refused '{}': {}", provider.id(),
                            pending.clientName(), failure.getMessage());
                    return Mono.just(redirect(pending.redirectUri(), builder -> builder
                            .queryParam("error", "access_denied")
                            .queryParam("error_description", failure.getMessage()), pending.clientState()));
                })
                .onErrorResume(StoreFullException.class, full -> {
                    log.warn("Could not issue a code to '{}': {}", pending.clientName(), full.getMessage());
                    return Mono.just(redirect(pending.redirectUri(), builder -> builder
                            .queryParam("error", "temporarily_unavailable")
                            .queryParam("error_description", "This server is handling too many "
                                    + "authorization requests. Try again shortly."),
                            pending.clientState()));
                })
                .onErrorResume(failure -> {
                    log.error("Could not complete the upstream exchange for '{}': {}",
                            pending.clientName(), failure.getMessage());
                    return Mono.just(redirect(pending.redirectUri(), builder -> builder
                            .queryParam("error", "server_error")
                            .queryParam("error_description",
                                    "This server could not complete the exchange with the provider."),
                            pending.clientState()));
                });
    }

    private static ResponseEntity<String> redirect(String redirectUri,
            java.util.function.UnaryOperator<UriComponentsBuilder> parameters, String clientState) {
        UriComponentsBuilder location = parameters.apply(UriComponentsBuilder.fromUriString(redirectUri));
        if (clientState != null) {
            location.queryParam("state", clientState);
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(location.encode(StandardCharsets.UTF_8).build().toUriString()))
                .build();
    }

    private static ResponseEntity<String> errorPage(HttpStatus status, String title, String detail) {
        return ResponseEntity.status(status)
                .contentType(MediaType.TEXT_PLAIN)
                .body(title + "\n\n" + detail + "\n");
    }
}
