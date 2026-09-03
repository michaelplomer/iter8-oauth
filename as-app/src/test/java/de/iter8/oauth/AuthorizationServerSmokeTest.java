package de.iter8.oauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Boots the whole authorization server with a Google identity provider configured, and checks that the
 * discovery surface an MCP client relies on is actually served: RFC 8414 metadata (advertising CIMD, public
 * clients and a jwks_uri), the JWKS itself (a signing key was generated for the run), and the authorize
 * endpoint's unknown-client path. No real Google is contacted — none of these paths reach it.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "iter8.oauth.issuer=https://auth.test",
                "iter8.oauth.default-provider=google",
                "iter8.oauth.providers.google.type=oidc-identity",
                "iter8.oauth.providers.google.client-id=test-client",
                "iter8.oauth.providers.google.client-secret=test-secret",
                "iter8.oauth.providers.google.authorization-uri=https://accounts.google.com/o/oauth2/v2/auth",
                "iter8.oauth.providers.google.token-uri=https://oauth2.googleapis.com/token",
                "iter8.oauth.providers.google.jwks-uri=https://www.googleapis.com/oauth2/v3/certs",
                "iter8.oauth.providers.google.requested-scope=openid email",
                "iter8.oauth.providers.google.allowed-hosted-domains=plomer.info",
                "iter8.oauth.providers.google.scopes-supported=whatable.read,whatable.write",
        })
class AuthorizationServerSmokeTest {

    @LocalServerPort
    int port;

    WebTestClient web;

    @BeforeEach
    void bindClient() {
        this.web = WebTestClient.bindToServer().baseUrl("http://localhost:" + this.port).build();
    }

    @Test
    void serves_authorization_server_metadata() {
        web.get().uri("/.well-known/oauth-authorization-server")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.issuer").isEqualTo("https://auth.test")
                .jsonPath("$.authorization_endpoint").isEqualTo("https://auth.test/oauth2/authorize")
                .jsonPath("$.token_endpoint").isEqualTo("https://auth.test/oauth2/token")
                .jsonPath("$.jwks_uri").isEqualTo("https://auth.test/.well-known/jwks.json")
                .jsonPath("$.client_id_metadata_document_supported").isEqualTo(true)
                .jsonPath("$.code_challenge_methods_supported[0]").isEqualTo("S256")
                .jsonPath("$.scopes_supported")
                .value(org.hamcrest.Matchers.hasItems("whatable.read", "whatable.write"));
    }

    @Test
    void publishes_a_jwks_signing_key() {
        web.get().uri("/.well-known/jwks.json")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // A throwaway signing pair is generated when none is configured, so exactly one key here.
                .jsonPath("$.keys.length()").isEqualTo(1)
                .jsonPath("$.keys[0].kty").isEqualTo("RSA")
                // Public parameters only — never the private exponent.
                .jsonPath("$.keys[0].d").doesNotExist();
    }

    @Test
    void refuses_an_authorization_request_from_an_unknown_client() {
        web.get().uri(builder -> builder.path("/oauth2/authorize")
                        .queryParam("client_id", "not-a-valid-url")
                        .queryParam("redirect_uri", "https://client.test/callback")
                        .queryParam("response_type", "code")
                        .build())
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody(String.class).value(body ->
                        org.assertj.core.api.Assertions.assertThat(body).contains("Unknown client"));
    }
}
