package de.iter8.oauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Boots the authorization server with an {@code oauth2-broker} provider (Oura-shaped) and no identity
 * provider, and checks it wires: the broker's scope is advertised, and — since nothing issues signed
 * identity tokens — no {@code jwks_uri} is published. This exercises the SEALED_CREDENTIAL (JWE) path, the
 * one oura-mcp validates against.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "iter8.oauth.issuer=https://auth.test",
                "iter8.oauth.default-provider=oura",
                "iter8.oauth.providers.oura.type=oauth2-broker",
                "iter8.oauth.providers.oura.client-id=oura-client",
                "iter8.oauth.providers.oura.client-secret=oura-secret",
                "iter8.oauth.providers.oura.authorization-uri=https://cloud.ouraring.com/oauth/authorize",
                "iter8.oauth.providers.oura.token-uri=https://api.ouraring.com/oauth/token",
                "iter8.oauth.providers.oura.scopes=daily,personal,heartrate",
                "iter8.oauth.providers.oura.scopes-supported=oura.read",
                // No jwe keys configured, so a throwaway SEALED_CREDENTIAL keypair is generated for the run.
        })
class AuthorizationServerBrokerTest {

    @LocalServerPort
    int port;

    WebTestClient web;

    @BeforeEach
    void bindClient() {
        this.web = WebTestClient.bindToServer().baseUrl("http://localhost:" + this.port).build();
    }

    @Test
    void advertises_the_broker_scope_and_publishes_no_jwks() {
        web.get().uri("/.well-known/oauth-authorization-server")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.scopes_supported")
                .value(org.hamcrest.Matchers.hasItem("oura.read"))
                // No identity provider is configured, so no signing keys are advertised.
                .jsonPath("$.jwks_uri").doesNotExist();
    }
}
