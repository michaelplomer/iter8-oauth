package de.iter8.oauth.as;

import java.net.URI;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;

import de.iter8.oauth.cimd.ClientAssertionVerifier;
import de.iter8.oauth.cimd.ClientIdMetadataResolver;
import de.iter8.oauth.token.EncryptionJwks;
import de.iter8.oauth.token.JweTokenCodec;
import de.iter8.oauth.token.RefreshTokenCodec;
import de.iter8.oauth.token.ResourceEncryptionKeyResolver;
import de.iter8.oauth.token.TokenModel;

/**
 * The token endpoint issues a sealed credential once its resource's key is discovered, waiting for it when it
 * is not cached yet, and answers anything that fails unexpectedly with an RFC 6749 error response.
 */
class TokenEndpointTests {

    private static final String ISSUER = "https://auth.test";

    private static final String RESOURCE = "https://oura.test/mcp";

    private static final String CLIENT = "https://client.test/metadata.json";

    private static final String REDIRECT = "https://client.test/callback";

    private static final String VERIFIER = "a-verifier-long-enough-to-satisfy-rfc-7636-section-4-1";

    @Test
    void a_token_request_waits_for_a_key_that_is_still_being_discovered() {
        JWK published = publishedKey();
        DiscoveringResourceEncryptionKeyResolver resolver = new DiscoveringResourceEncryptionKeyResolver(
                Set.of(RESOURCE), Duration.ofMinutes(15), Clock.systemUTC(),
                resource -> Mono.just(published).delayElement(Duration.ofMillis(200)));
        TokenCodecs codecs = new TokenCodecs(new JweTokenCodec(resolver, null, ISSUER), null, resolver);
        Fixture fixture = new Fixture(codecs);

        ResponseEntity<Map<String, Object>> response = fixture.redeem(fixture.issueCode());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("access_token");
    }

    @Test
    void a_failure_while_issuing_is_answered_with_an_oauth_error() {
        ResourceEncryptionKeyResolver noKeys = resource -> Optional.empty();
        TokenCodecs codecs = new TokenCodecs(new JweTokenCodec(noKeys, null, ISSUER), null);
        Fixture fixture = new Fixture(codecs);

        ResponseEntity<Map<String, Object>> response = fixture.redeem(fixture.issueCode());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).containsEntry("error", "server_error").containsKey("error_description");
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    private static final class Fixture {

        private final AuthorizationCodeStore codes = new AuthorizationCodeStore();

        private final TokenEndpoint endpoint;

        Fixture(TokenCodecs codecs) {
            ClientIdMetadataResolver clients = new ClientIdMetadataResolver(WebClient.builder(),
                    Duration.ofMinutes(5), false);
            this.endpoint = new TokenEndpoint(
                    new ProviderRegistry(List.of(new BrokeringProvider()), Map.of(RESOURCE, "oura"), null),
                    this.codes, codecs, new RefreshTokenCodec(null, ISSUER),
                    new RefreshTokenLedger(Duration.ofDays(30)), clients,
                    new ClientAssertionVerifier(clients, Duration.ofMinutes(5)),
                    new AuthorizationServerUris(ISSUER),
                    new AsSettings(Duration.ofMinutes(1), Duration.ofHours(1), Duration.ofDays(30),
                            Duration.ofMinutes(5), List.of()));
        }

        String issueCode() {
            return this.codes.store(new IssuedAuthorizationCode("oura", CLIENT, REDIRECT,
                    PkceVerifier.challengeFor(VERIFIER), "none",
                    "oura.read", RESOURCE,
                    UpstreamResult.credential("acct-1", "oura.read", "UPSTREAM-ACCESS", "UPSTREAM-REFRESH",
                            Instant.now().plusSeconds(3600)),
                    Instant.now().plusSeconds(60)));
        }

        ResponseEntity<Map<String, Object>> redeem(String code) {
            MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
                    .post(AsPaths.TOKEN_PATH)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("grant_type=authorization_code&code=" + code + "&client_id=" + CLIENT
                            + "&redirect_uri=" + REDIRECT + "&code_verifier=" + VERIFIER));
            return this.endpoint.token(exchange).block(Duration.ofSeconds(5));
        }
    }

    private static final class BrokeringProvider implements UpstreamProvider {

        @Override
        public String id() {
            return "oura";
        }

        @Override
        public TokenModel tokenModel() {
            return TokenModel.SEALED_CREDENTIAL;
        }

        @Override
        public List<String> scopesSupported() {
            return List.of("oura.read");
        }

        @Override
        public URI authorizationRequestUri(String state, String callbackUri, String requestedScope) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Mono<UpstreamResult> completeCallback(String code, String callbackUri,
                PendingAuthorization pending) {
            return Mono.error(new UnsupportedOperationException());
        }

        @Override
        public Mono<UpstreamResult> refresh(UpstreamResult previous) {
            return Mono.error(new UnsupportedOperationException());
        }
    }

    private static JWK publishedKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            RSAPublicKey publicKey = (RSAPublicKey) generator.generateKeyPair().getPublic();
            return EncryptionJwks.rsaEncryptionKey(publicKey, null, null).toPublicJWK();
        }
        catch (Exception failure) {
            throw new RuntimeException(failure);
        }
    }
}
