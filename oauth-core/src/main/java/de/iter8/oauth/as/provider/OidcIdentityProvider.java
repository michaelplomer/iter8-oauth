package de.iter8.oauth.as.provider;

import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import de.iter8.oauth.as.PendingAuthorization;
import de.iter8.oauth.as.UpstreamAuthorizationException;
import de.iter8.oauth.as.UpstreamProvider;
import de.iter8.oauth.as.UpstreamResult;
import de.iter8.oauth.token.TokenModel;

/**
 * An OIDC identity provider — Google, and anything else that speaks OpenID Connect. It authenticates the
 * user and returns their verified identity ({@link TokenModel#SIGNED_IDENTITY}); it carries no upstream
 * credential, so this server's tokens are signed rather than encrypted.
 *
 * <p>Authorization is a gate applied here, at the callback: the verified account is admitted only when its
 * hosted domain ({@code hd}, a Workspace signal — not the email suffix) is on the allowed list, or its email
 * is on the allowlist. Everything else authenticated is refused with an
 * {@link UpstreamAuthorizationException}.
 */
public class OidcIdentityProvider implements UpstreamProvider {

    /**
     * @param clientId this server's OAuth client id at the provider
     * @param clientSecret this server's OAuth client secret
     * @param authorizationUri the provider's authorization endpoint
     * @param tokenUri the provider's token endpoint
     * @param jwksUri the provider's JWKS, for verifying the id_token signature
     * @param acceptedIssuers the {@code iss} values accepted in the id_token
     * @param requestedScope the scope to request; must yield an id_token with email (e.g. "openid email")
     * @param allowedHostedDomains Workspace hosted domains admitted wholesale (matched against {@code hd})
     * @param allowedEmails individual external accounts admitted (matched case-insensitively)
     * @param scopesSupported the scopes this authorization server advertises for this provider
     */
    public record Config(String clientId, String clientSecret, String authorizationUri, String tokenUri,
            String jwksUri, List<String> acceptedIssuers, String requestedScope,
            List<String> allowedHostedDomains, List<String> allowedEmails, List<String> scopesSupported) {
    }

    private final String id;

    private final Config config;

    private final WebClient webClient;

    private final JWKSource<SecurityContext> jwkSource;

    public OidcIdentityProvider(String id, Config config, WebClient.Builder webClientBuilder) {
        this.id = id;
        this.config = config;
        this.webClient = webClientBuilder.build();
        try {
            URL jwksUrl = URI.create(config.jwksUri()).toURL();
            this.jwkSource = JWKSourceBuilder.create(jwksUrl).build();
        }
        catch (Exception failure) {
            throw new IllegalStateException("The provider jwks_uri '" + config.jwksUri()
                    + "' is not a usable URL.", failure);
        }
    }

    @Override
    public String id() {
        return this.id;
    }

    @Override
    public TokenModel tokenModel() {
        return TokenModel.SIGNED_IDENTITY;
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
                .queryParam("scope", this.config.requestedScope())
                .queryParam("state", state)
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString());
    }

    @Override
    public Mono<UpstreamResult> completeCallback(String code, String callbackUri,
            PendingAuthorization pending) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", callbackUri);
        form.add("client_id", this.config.clientId());
        form.add("client_secret", this.config.clientSecret());

        Mono<TokenResponse> exchange = this.webClient.post()
                .uri(this.config.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(form)
                .retrieve()
                .bodyToMono(TokenResponse.class)
                .onErrorMap(failure -> !(failure instanceof UpstreamTokenException),
                        failure -> new UpstreamTokenException(
                                "The identity provider refused the token request: " + failure.getMessage(),
                                failure));

        // Verification fetches JWKS and does crypto, both blocking, so it runs off the event loop.
        return exchange.flatMap(response -> Mono.fromCallable(
                        () -> verifyAndGate(response.idToken(), pending.scope()))
                .subscribeOn(Schedulers.boundedElastic()));
    }

    @Override
    public Mono<UpstreamResult> refresh(UpstreamResult previous) {
        // Identity is re-issued from the sealed identity without a round trip, within the refresh token's
        // own lifetime. When that expires the user authenticates again. The allowlist is applied again first,
        // so removing someone from it takes effect at their next refresh rather than when the token expires.
        Map<String, Object> identity =
                (previous.identityClaims() == null) ? Map.of() : previous.identityClaims();
        String email = (identity.get("email") instanceof String value) ? value : null;
        String hostedDomain = (identity.get("hd") instanceof String value) ? value : null;
        if (email == null || !admits(email, hostedDomain)) {
            return Mono.error(new UpstreamAuthorizationException(
                    "This account is no longer admitted by the server's allowlist."));
        }
        return Mono.just(UpstreamResult.identity(previous.subject(), previous.scope(), identity));
    }

    private UpstreamResult verifyAndGate(String idToken, String scope) {
        if (idToken == null || idToken.isBlank()) {
            throw new UpstreamTokenException("The identity provider returned no id_token.");
        }
        JWTClaimsSet claims;
        try {
            SignedJWT jwt = SignedJWT.parse(idToken);
            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSKeySelector(
                    new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, this.jwkSource));
            claims = processor.process(jwt, null);
        }
        catch (Exception failure) {
            throw new UpstreamTokenException("The id_token did not verify: " + failure.getMessage());
        }

        try {
            if (!this.config.acceptedIssuers().contains(claims.getIssuer())) {
                throw new UpstreamTokenException("The id_token issuer '" + claims.getIssuer()
                        + "' is not accepted.");
            }
            if (claims.getAudience() == null || !claims.getAudience().contains(this.config.clientId())) {
                throw new UpstreamTokenException("The id_token audience does not name this server's client.");
            }
            if (!Boolean.TRUE.equals(claims.getBooleanClaim("email_verified"))) {
                throw new UpstreamAuthorizationException("The Google account's email is not verified.");
            }
            String email = claims.getStringClaim("email");
            String hostedDomain = claims.getStringClaim("hd");
            String name = claims.getStringClaim("name");
            String subject = claims.getSubject();

            if (!admits(email, hostedDomain)) {
                throw new UpstreamAuthorizationException("The account " + email + " is not permitted: its "
                        + "hosted domain is not allowed and it is not on the allowlist.");
            }

            Map<String, Object> identity = new LinkedHashMap<>();
            identity.put("email", email);
            if (hostedDomain != null) {
                identity.put("hd", hostedDomain);
            }
            if (name != null) {
                identity.put("name", name);
            }
            identity.put("oidc_sub", subject);
            // Subject is the email: a stable, human-meaningful id the downstream uses as its user key.
            return UpstreamResult.identity(email, scope, identity);
        }
        catch (ParseException failure) {
            throw new UpstreamTokenException("The id_token claims are malformed: " + failure.getMessage());
        }
    }

    /**
     * The authorization gate: a verified account is admitted when its Workspace hosted domain is allowed,
     * or its email is on the allowlist. Package-visible so the decision can be tested without a token.
     *
     * @param email the verified email (matched case-insensitively against the allowlist)
     * @param hostedDomain the {@code hd} claim, or {@code null} for a non-Workspace (e.g. gmail) account
     * @return whether the account is permitted
     */
    boolean admits(String email, String hostedDomain) {
        boolean domainAdmitted = hostedDomain != null
                && this.config.allowedHostedDomains().contains(hostedDomain);
        boolean emailAdmitted = email != null
                && this.config.allowedEmails().stream().anyMatch(email::equalsIgnoreCase);
        return domainAdmitted || emailAdmitted;
    }

    record TokenResponse(@JsonProperty("id_token") String idToken) {
    }
}
