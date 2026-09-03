package de.iter8.oauth.rs;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Answers an unauthenticated MCP request with the {@code WWW-Authenticate} header the MCP authorization
 * specification requires, including the {@code resource_metadata} pointer.
 *
 * <p>That pointer is the whole discovery mechanism: a client that gets a 401 reads {@code resource_metadata},
 * fetches the document, learns which authorization server to talk to and retries with a token. Spring
 * Security's own entry point predates RFC 9728 and does not emit the parameter, so the header is built here.
 */
@RequiredArgsConstructor
@Slf4j
public class McpBearerTokenEntryPoint implements ServerAuthenticationEntryPoint {

    private final String resourceMetadataUrl;

    private final String realm;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException exception) {
        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("realm", this.realm);

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        if (exception instanceof InvalidBearerTokenException
                && ((InvalidBearerTokenException) exception).getError() instanceof BearerTokenError error) {
            parameters.put("error", error.getErrorCode());
            if (error.getDescription() != null) {
                parameters.put("error_description", error.getDescription());
            }
            status = HttpStatus.valueOf(error.getHttpStatus().value());
        }
        parameters.put("resource_metadata", this.resourceMetadataUrl);

        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String presented = (authorization == null) ? "no Authorization header"
                : authorization.regionMatches(true, 0, "Bearer ", 0, 7)
                        ? ("a bearer token of " + (authorization.length() - 7) + " characters, which was "
                                + "refused")
                        : "an Authorization header that is not a bearer token";
        log.info("Answering {} {} with a {} challenge; the request carried {}. Pointing at {}.",
                exchange.getRequest().getMethod(),
                exchange.getRequest().getPath().pathWithinApplication(), status.value(), presented,
                this.resourceMetadataUrl);
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, header(parameters));
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        String body = """
                {"error":"unauthorized","error_description":"An OAuth 2.0 access token is required.",\
                "resource_metadata":"%s"}""".formatted(this.resourceMetadataUrl);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory()
                .wrap(body.getBytes(StandardCharsets.UTF_8))));
    }

    private static String header(Map<String, String> parameters) {
        StringBuilder header = new StringBuilder("Bearer ");
        boolean first = true;
        for (Map.Entry<String, String> parameter : parameters.entrySet()) {
            if (!first) {
                header.append(", ");
            }
            first = false;
            header.append(parameter.getKey())
                    .append("=\"")
                    .append(parameter.getValue().replace("\"", ""))
                    .append('"');
        }
        return header.toString();
    }
}
