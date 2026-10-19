package de.iter8.oauth.as;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Receives the user's answer from the consent page.
 *
 * <p>Allowing sends the user on to the upstream provider; denying, or any other answer, returns
 * {@code access_denied} to the client. Either way the decision only counts when the browser presents the
 * cookie the consent page set, so a decision cannot be submitted on someone else's behalf. The cookie is
 * {@code SameSite=Strict} as well, so a cross-site form post never carries it in the first place.
 */
@RequiredArgsConstructor
@Slf4j
@RestController
public class ConsentEndpoint {

    private static final String COOKIE_PREFIX = "iter8_consent_";

    private final ProviderRegistry providers;

    private final AuthorizationServerUris uris;

    private final PendingAuthorizationStore pendingAuthorizations;

    private final ConsentStore consents;

    private final AsSettings settings;

    @PostMapping(path = AsPaths.CONSENT_PATH, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Mono<ResponseEntity<String>> decide(ServerWebExchange exchange) {
        return exchange.getFormData().map(form -> decide(form, exchange));
    }

    private ResponseEntity<String> decide(MultiValueMap<String, String> form, ServerWebExchange exchange) {
        String consentId = form.getFirst("consent_id");
        if (consentId == null || consentId.isBlank()) {
            return AuthorizationEndpoint.errorPage(HttpStatus.BAD_REQUEST, "Missing consent request",
                    "The form did not identify which request it answers.");
        }
        String formAction = this.uris.absolute(AsPaths.CONSENT_PATH);
        String clearCookie = expiredCookie(consentId, formAction);

        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(COOKIE_PREFIX + consentId);
        Optional<PendingAuthorization> found =
                this.consents.consume(consentId, (cookie == null) ? null : cookie.getValue());
        if (found.isEmpty()) {
            log.warn("Refused a consent decision: the request is unknown, has expired, or was answered from "
                    + "a browser other than the one that was shown the consent page.");
            return withCookie(AuthorizationEndpoint.errorPage(HttpStatus.BAD_REQUEST,
                    "This request is no longer valid",
                    "It has expired, was already answered, or was opened in another browser. Return to the "
                            + "app and start again."), clearCookie);
        }
        PendingAuthorization authorization = found.get();

        if (!"allow".equals(form.getFirst("decision"))) {
            log.info("The user denied '{}' ({}).", authorization.clientName(), authorization.clientId());
            return withCookie(AuthorizationEndpoint.redirectError(authorization.redirectUri(),
                    authorization.clientState(), "access_denied", "The user denied the request."),
                    clearCookie);
        }

        UpstreamProvider provider = this.providers.byId(authorization.providerId());
        if (provider == null) {
            log.error("Provider '{}' disappeared while a consent page was open.", authorization.providerId());
            return withCookie(AuthorizationEndpoint.errorPage(HttpStatus.INTERNAL_SERVER_ERROR,
                    "This server is misconfigured",
                    "The upstream provider for this request is not configured."), clearCookie);
        }
        try {
            // The upstream leg gets its own window from now, however long the user spent on the page.
            URI location = UpstreamRedirect.start(this.pendingAuthorizations, this.uris, provider,
                    authorization.withExpiry(PendingAuthorizationStore.expiryFrom(
                            this.settings.authorizationCodeTtl())));
            log.info("The user allowed '{}' ({}); sending them to provider '{}'.", authorization.clientName(),
                    authorization.clientId(), provider.id());
            return ResponseEntity.status(HttpStatus.SEE_OTHER)
                    .header(HttpHeaders.SET_COOKIE, clearCookie)
                    .location(location)
                    .build();
        }
        catch (StoreFullException full) {
            log.warn("Refused to continue an allowed request from {}: {}", authorization.clientId(),
                    full.getMessage());
            return withCookie(AuthorizationEndpoint.redirectError(authorization.redirectUri(),
                    authorization.clientState(), "temporarily_unavailable",
                    "This server is handling too many authorization requests. Try again shortly."),
                    clearCookie);
        }
    }

    /**
     * The cookie that ties a consent page to the browser it was shown in. It is named after the consent
     * request, so two consent pages open at once do not overwrite each other's cookie, and it is only sent to
     * the consent endpoint.
     *
     * @param consentId the request awaiting consent
     * @param binding the random value to set
     * @param formAction the absolute URL of the consent endpoint, which decides the cookie's path and whether
     *     it is marked secure
     * @param ttl how long the consent page stays answerable
     * @return the {@code Set-Cookie} header value
     */
    static String bindingCookie(String consentId, String binding, String formAction, Duration ttl) {
        return cookie(consentId, binding, formAction, ttl);
    }

    private static String expiredCookie(String consentId, String formAction) {
        return cookie(consentId, "", formAction, Duration.ZERO);
    }

    private static String cookie(String consentId, String value, String formAction, Duration maxAge) {
        URI action = URI.create(formAction);
        return ResponseCookie.from(COOKIE_PREFIX + consentId, value)
                .path(action.getPath())
                .httpOnly(true)
                .secure("https".equals(action.getScheme()))
                .sameSite("Strict")
                .maxAge(maxAge)
                .build()
                .toString();
    }

    private static ResponseEntity<String> withCookie(ResponseEntity<String> response, String setCookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.addAll(response.getHeaders());
        headers.add(HttpHeaders.SET_COOKIE, setCookie);
        return new ResponseEntity<>(response.getBody(), headers, response.getStatusCode());
    }
}
