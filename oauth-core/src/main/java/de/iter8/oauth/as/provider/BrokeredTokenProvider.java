package de.iter8.oauth.as.provider;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import de.iter8.oauth.as.PendingAuthorization;
import de.iter8.oauth.as.UpstreamProvider;
import de.iter8.oauth.as.UpstreamResult;
import de.iter8.oauth.token.TokenModel;

/**
 * A brokering provider for an OAuth 2 authorization-code upstream that yields an API credential — Oura, and
 * anything else shaped like it. The upstream access token is sealed into this server's tokens
 * ({@link TokenModel#SEALED_CREDENTIAL}) and never reaches the client.
 */
public class BrokeredTokenProvider implements UpstreamProvider {

    /**
     * @param clientId the application's client id at the upstream
     * @param clientSecret the application's client secret at the upstream
     * @param authorizationUri the upstream authorization endpoint
     * @param tokenUri the upstream token endpoint
     * @param upstreamScopes the scopes to request upstream
     * @param scopesSupported the scopes this authorization server advertises for this provider
     */
    public record Config(String clientId, String clientSecret, String authorizationUri, String tokenUri,
            List<String> upstreamScopes, List<String> scopesSupported) {
    }

    private final String id;

    private final Config config;

    private final WebClient webClient;

    public BrokeredTokenProvider(String id, Config config, WebClient.Builder webClientBuilder) {
        this.id = id;
        this.config = config;
        this.webClient = webClientBuilder.build();
    }

    @Override
    public String id() {
        return this.id;
    }

    @Override
    public TokenModel tokenModel() {
        return TokenModel.SEALED_CREDENTIAL;
    }

    @Override
    public List<String> scopesSupported() {
        return this.config.scopesSupported();
    }

    @Override
    public URI authorizationRequestUri(String state, String callbackUri, String requestedScope) {
        return URI.create(UriComponentsBuilder.fromUriString(this.config.authorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", this.config.clientId())
                .queryParam("redirect_uri", callbackUri)
                .queryParam("scope", String.join(" ", this.config.upstreamScopes()))
                .queryParam("state", state)
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString());
    }

    @Override
    public Mono<UpstreamResult> completeCallback(String code, String callbackUri,
            PendingAuthorization pending) {
        MultiValueMap<String, String> form = credentials();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", callbackUri);
        // Subject is null: a bare broker learns no stable account id without a further upstream call. The
        // resource server relies on the sealed credential, not on this.
        return post(form, pending.scope(), null);
    }

    @Override
    public Mono<UpstreamResult> refresh(UpstreamResult previous) {
        MultiValueMap<String, String> form = credentials();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", previous.refreshCredential());
        return post(form, previous.scope(), previous.subject());
    }

    private MultiValueMap<String, String> credentials() {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", this.config.clientId());
        form.add("client_secret", this.config.clientSecret());
        return form;
    }

    private Mono<UpstreamResult> post(MultiValueMap<String, String> form, String scope, String subject) {
        return this.webClient.post()
                .uri(this.config.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .map(response -> {
                    if (response.accessToken() == null || response.accessToken().isBlank()) {
                        throw new UpstreamTokenException("The upstream token response carried no "
                                + "access_token.");
                    }
                    // A missing expires_in is treated as already expired, so the refresh path runs rather
                    // than a call failing upstream with a token this server thought was good.
                    Instant expiresAt = (response.expiresIn() != null)
                            ? Instant.now().plusSeconds(response.expiresIn()) : Instant.now();
                    return UpstreamResult.credential(subject, scope, response.accessToken(),
                            response.refreshToken(), expiresAt);
                })
                .onErrorMap(failure -> !(failure instanceof UpstreamTokenException),
                        failure -> new UpstreamTokenException(
                                "The upstream refused the token request: " + failure.getMessage(), failure));
    }

    record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("refresh_token") String refreshToken,
            @JsonProperty("expires_in") Long expiresIn,
            @JsonProperty("scope") String scope
    ) {
    }
}
