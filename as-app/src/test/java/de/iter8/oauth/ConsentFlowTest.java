package de.iter8.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * The consent page between client validation and the upstream provider. The test server serves its own
 * client metadata documents on loopback, which {@code allow-loopback-clients} permits, so the whole flow runs
 * without the network up to the redirect to the upstream provider.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                "iter8.oauth.issuer=https://auth.test",
                "iter8.oauth.allow-loopback-clients=true",
                "iter8.oauth.default-provider=google",
                "iter8.oauth.providers.google.type=oidc-identity",
                "iter8.oauth.providers.google.client-id=test-client",
                "iter8.oauth.providers.google.client-secret=test-secret",
                "iter8.oauth.providers.google.authorization-uri=https://accounts.google.com/o/oauth2/v2/auth",
                "iter8.oauth.providers.google.token-uri=https://oauth2.googleapis.com/token",
                "iter8.oauth.providers.google.jwks-uri=https://www.googleapis.com/oauth2/v3/certs",
                "iter8.oauth.providers.google.requested-scope=openid email",
                "iter8.oauth.providers.google.allowed-hosted-domains=example.com",
                "iter8.oauth.providers.google.scopes-supported=notes.read",
        })
@Import(ConsentFlowTest.ClientDocuments.class)
class ConsentFlowTest {

    private static final int PORT = freePort();

    private static final String REDIRECT_URI = "http://localhost:9/callback";

    private static final Pattern CONSENT_ID = Pattern.compile("name=\"consent_id\" value=\"([^\"]+)\"");

    WebTestClient web;

    @DynamicPropertySource
    static void port(DynamicPropertyRegistry registry) {
        registry.add("server.port", () -> PORT);
        registry.add("iter8.oauth.trusted-clients", () -> clientId("trusted"));
    }

    @BeforeEach
    void bindClient() {
        this.web = WebTestClient.bindToServer().baseUrl("http://localhost:" + PORT).build();
    }

    @Test
    void showsAConsentPageForAnUntrustedClient() {
        EntityExchangeResult<String> page = authorize("notes");

        assertThat(page.getStatus().value()).isEqualTo(200);
        assertThat(page.getResponseHeaders().getContentType()).isNotNull()
                .matches(type -> type.isCompatibleWith(MediaType.TEXT_HTML));
        assertThat(page.getResponseHeaders().getFirst("X-Frame-Options")).isEqualTo("DENY");
        assertThat(page.getResponseHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(page.getResponseBody())
                .contains(clientId("notes"))
                .contains("&lt;script&gt;")
                .doesNotContain("<script>");
        assertThat(page.getResponseHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .startsWith("iter8_consent_")
                .contains("HttpOnly")
                .contains("SameSite=Strict");
    }

    @Test
    void allowingSendsTheUserToTheUpstreamProvider() {
        Consent consent = consentFrom(authorize("notes"));

        this.web.post().uri("/oauth2/consent")
                .cookie(consent.cookieName(), consent.cookieValue())
                .body(BodyInserters.fromFormData("consent_id", consent.id()).with("decision", "allow"))
                .exchange()
                .expectStatus().isSeeOther()
                .expectHeader().value(HttpHeaders.LOCATION, location -> assertThat(location)
                        .startsWith("https://accounts.google.com/o/oauth2/v2/auth")
                        .contains("state="));
    }

    @Test
    void denyingReturnsAccessDeniedToTheClient() {
        Consent consent = consentFrom(authorize("notes"));

        this.web.post().uri("/oauth2/consent")
                .cookie(consent.cookieName(), consent.cookieValue())
                .body(BodyInserters.fromFormData("consent_id", consent.id()).with("decision", "deny"))
                .exchange()
                .expectStatus().isFound()
                .expectHeader().value(HttpHeaders.LOCATION, location -> {
                    Map<String, List<String>> query = UriComponentsBuilder.fromUri(URI.create(location))
                            .build().getQueryParams();
                    assertThat(location).startsWith(REDIRECT_URI);
                    assertThat(query.get("error")).containsExactly("access_denied");
                    assertThat(query.get("state")).containsExactly("client-state");
                });
    }

    @Test
    void refusesAnApprovalFromAnotherBrowserAndSpendsTheRequest() {
        Consent consent = consentFrom(authorize("notes"));

        // Without the cookie, as from a browser that was never shown this consent page.
        this.web.post().uri("/oauth2/consent")
                .body(BodyInserters.fromFormData("consent_id", consent.id()).with("decision", "allow"))
                .exchange()
                .expectStatus().isBadRequest();

        // The failed attempt spent the request, so the right browser cannot use it afterwards either.
        this.web.post().uri("/oauth2/consent")
                .cookie(consent.cookieName(), consent.cookieValue())
                .body(BodyInserters.fromFormData("consent_id", consent.id()).with("decision", "allow"))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    void sendsATrustedClientStraightToTheUpstreamProvider() {
        EntityExchangeResult<String> response = authorize("trusted");

        assertThat(response.getStatus().value()).isEqualTo(302);
        assertThat(String.valueOf(response.getResponseHeaders().getLocation()))
                .startsWith("https://accounts.google.com/");
    }

    private EntityExchangeResult<String> authorize(String client) {
        return this.web.get().uri(builder -> builder.path("/oauth2/authorize")
                        .queryParam("client_id", clientId(client))
                        .queryParam("redirect_uri", REDIRECT_URI)
                        .queryParam("response_type", "code")
                        .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("state", "client-state")
                        .queryParam("scope", "notes.read")
                        .build())
                .exchange()
                .expectBody(String.class)
                .returnResult();
    }

    private static Consent consentFrom(EntityExchangeResult<String> page) {
        Matcher id = CONSENT_ID.matcher(page.getResponseBody());
        assertThat(id.find()).as("consent page carries a consent_id").isTrue();
        String setCookie = page.getResponseHeaders().getFirst(HttpHeaders.SET_COOKIE);
        String pair = setCookie.substring(0, setCookie.indexOf(';'));
        int equals = pair.indexOf('=');
        return new Consent(id.group(1), pair.substring(0, equals), pair.substring(equals + 1));
    }

    private static String clientId(String name) {
        return "http://localhost:" + PORT + "/clients/" + name + ".json";
    }

    private static int freePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
        catch (IOException failure) {
            throw new IllegalStateException(failure);
        }
    }

    private record Consent(String id, String cookieName, String cookieValue) {
    }

    /**
     * Client metadata documents served by the test server itself. The untrusted client's name carries markup,
     * to check that the consent page escapes what a client says about itself.
     */
    @TestConfiguration
    static class ClientDocuments {

        @Bean
        RouterFunction<ServerResponse> clientDocuments() {
            return RouterFunctions.route(GET("/clients/{name}.json"), request -> {
                String name = request.pathVariable("name");
                Map<String, Object> document = Map.of(
                        "client_id", clientId(name),
                        "client_name", "notes".equals(name) ? "Notes <script>alert(1)</script>" : "Trusted",
                        "redirect_uris", List.of(REDIRECT_URI),
                        "token_endpoint_auth_method", "none");
                return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValue(document);
            });
        }
    }
}
