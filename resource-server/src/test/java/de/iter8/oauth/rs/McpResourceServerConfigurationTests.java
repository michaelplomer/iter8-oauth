package de.iter8.oauth.rs;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * Starts a minimal reactive app with this library and a stub MCP endpoint, to check how
 * {@code iter8.resource-server.enabled} and the token validation mode decide what the endpoint accepts.
 */
class McpResourceServerConfigurationTests {

    @Test
    void refusesToStartWhenEnabledIsNotSet() {
        assertThatThrownBy(() -> start().close())
                .rootCause()
                .hasMessageContaining("iter8.resource-server.enabled is not set");
    }

    @Test
    void acceptsEveryRequestWhenExplicitlyDisabled() {
        try (ConfigurableApplicationContext context = start("iter8.resource-server.enabled=false")) {
            client(context).get().uri("/mcp").exchange().expectStatus().isOk();
        }
    }

    @Test
    void treatsRelaxedSpellingsOfTrueAsEnabled() {
        try (ConfigurableApplicationContext context = start(
                "iter8.resource-server.enabled=on",
                "iter8.resource-server.resource=https://notes.example.com/mcp",
                "iter8.resource-server.authorization-servers=https://auth.example.com")) {

            client(context).get().uri("/mcp").exchange()
                    .expectStatus().isUnauthorized()
                    .expectHeader().value(HttpHeaders.WWW_AUTHENTICATE,
                            challenge -> assertThat(challenge).contains("resource_metadata="));
            client(context).get().uri("/.well-known/oauth-protected-resource/mcp").exchange()
                    .expectStatus().isOk();
        }
    }

    @Test
    void refusesToStartInJweModeWithoutAnEncryptionKey() {
        assertThatThrownBy(() -> start(
                "iter8.resource-server.enabled=true",
                "iter8.resource-server.token-validation=jwe",
                "iter8.resource-server.authorization-servers=https://auth.example.com").close())
                .rootCause()
                .hasMessageContaining("no encryption key is configured");
    }

    private static ConfigurableApplicationContext start(String... properties) {
        String[] withPort = new String[properties.length + 1];
        System.arraycopy(properties, 0, withPort, 0, properties.length);
        withPort[properties.length] = "server.port=0";
        return new SpringApplicationBuilder(StubMcpServer.class)
                .web(WebApplicationType.REACTIVE)
                .properties(withPort)
                .run();
    }

    private static WebTestClient client(ConfigurableApplicationContext context) {
        int port = ((WebServerApplicationContext) context).getWebServer().getPort();
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
    }

    @SpringBootConfiguration
    @EnableAutoConfiguration
    static class StubMcpServer {

        @Bean
        RouterFunction<ServerResponse> mcpEndpoint() {
            return RouterFunctions.route(GET("/mcp"), request -> ServerResponse.ok().bodyValue("ok"));
        }
    }
}
