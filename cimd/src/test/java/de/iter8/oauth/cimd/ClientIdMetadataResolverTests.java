package de.iter8.oauth.cimd;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

class ClientIdMetadataResolverTests {

    @Test
    void reports_a_failed_connection_without_saying_where_or_why() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        // Loopback is only reachable here because the test enables it; the point is what a caller learns.
        ClientIdMetadataResolver resolver =
                new ClientIdMetadataResolver(WebClient.builder(), Duration.ofMinutes(15), true);

        StepVerifier.create(resolver.resolve("http://localhost:" + closedPort + "/client.json"))
                .expectErrorSatisfies(failure -> assertThat(failure)
                        .isInstanceOf(ClientIdMetadataException.class)
                        .hasMessage("Could not fetch the client metadata document."))
                .verify(Duration.ofSeconds(10));
    }
}
