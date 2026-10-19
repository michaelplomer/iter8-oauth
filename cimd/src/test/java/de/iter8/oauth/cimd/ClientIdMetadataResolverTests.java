package de.iter8.oauth.cimd;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

class ClientIdMetadataResolverTests {

    private static final Duration CACHE_TTL = Duration.ofMinutes(15);

    @Test
    void reports_a_failed_connection_without_saying_where_or_why() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        // Loopback is only reachable here because the test enables it; the point is what a caller learns.
        ClientIdMetadataResolver resolver =
                new ClientIdMetadataResolver(WebClient.builder(), CACHE_TTL, true);

        StepVerifier.create(resolver.resolve("http://localhost:" + closedPort + "/client.json"))
                .expectErrorSatisfies(failure -> assertThat(failure)
                        .isInstanceOf(ClientIdMetadataException.class)
                        .hasMessage("Could not fetch the client metadata document."))
                .verify(Duration.ofSeconds(10));
    }

    @Test
    void refuses_a_host_that_resolves_to_a_special_use_address_in_a_single_lookup() {
        AtomicInteger lookups = new AtomicInteger();
        ClientIdMetadataResolver resolver = new ClientIdMetadataResolver(WebClient.builder(), CACHE_TTL,
                false, host -> {
                    lookups.incrementAndGet();
                    return new InetAddress[] {InetAddress.getByAddress(host, new byte[] {10, 0, 0, 5})};
                });

        StepVerifier.create(resolver.resolve("https://metadata.test/client.json"))
                .expectErrorSatisfies(failure -> assertThat(failure)
                        .isInstanceOf(ClientIdMetadataException.class)
                        .hasMessage("Could not fetch the client metadata document."))
                .verify(Duration.ofSeconds(10));
        // One lookup, made by the HTTP client while connecting: there is no separate check to race against.
        assertThat(lookups).hasValue(1);
    }

    @Test
    void connects_to_the_address_it_checked_even_if_the_dns_answer_changes() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        String clientId = "http://localhost:" + server.getAddress().getPort() + "/client.json";
        server.createContext("/client.json", exchange -> {
            byte[] body = ("{\"client_id\":\"" + clientId + "\","
                    + "\"redirect_uris\":[\"http://localhost:9/cb\"],"
                    + "\"token_endpoint_auth_method\":\"none\"}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        try {
            // The first answer is loopback, which this test allows. Any later answer would be a private
            // address the check refuses, as a rebinding host would give, so a second lookup to connect would
            // make the fetch fail.
            AtomicInteger lookups = new AtomicInteger();
            ClientIdMetadataResolver resolver = new ClientIdMetadataResolver(WebClient.builder(), CACHE_TTL,
                    true, host -> new InetAddress[] {lookups.incrementAndGet() == 1
                            ? InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})
                            : InetAddress.getByAddress(host, new byte[] {10, 0, 0, 5})});

            StepVerifier.create(resolver.resolve(clientId))
                    .expectNextMatches(metadata -> metadata.clientId().equals(clientId))
                    .verifyComplete();
            assertThat(lookups).hasValue(1);
        }
        finally {
            server.stop(0);
        }
    }

    @Test
    void refuses_a_special_use_address_written_as_an_ip_literal_without_a_lookup() {
        AtomicInteger lookups = new AtomicInteger();
        ClientIdMetadataResolver resolver = new ClientIdMetadataResolver(WebClient.builder(), CACHE_TTL,
                false, host -> {
                    lookups.incrementAndGet();
                    return InetAddress.getAllByName(host);
                });

        StepVerifier.create(resolver.resolve("https://169.254.169.254/client.json"))
                .expectError(ClientIdMetadataException.class)
                .verify(Duration.ofSeconds(10));
        StepVerifier.create(resolver.resolve("https://[fd00::1]/client.json"))
                .expectError(ClientIdMetadataException.class)
                .verify(Duration.ofSeconds(10));
        assertThat(lookups).hasValue(0);
    }
}
