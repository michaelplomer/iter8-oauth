package de.iter8.oauth.rs;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Serves the RFC 9728 protected resource metadata document MCP clients read to learn which authorization
 * server to get a token from. Registered only when inbound authorization is enabled: publishing a document
 * that names no authorization server would leave a client with nowhere to go.
 */
@RequiredArgsConstructor
@Slf4j
@RestController
@ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "true")
public class ProtectedResourceMetadataController {

    private final McpResourceServerProperties properties;

    @GetMapping(path = McpResourceServerProperties.METADATA_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata(ServerWebExchange exchange) {
        return ResponseEntity.ok(document(exchange));
    }

    /**
     * RFC 9728 inserts the well-known segment between the authority and the resource's path, so a resource
     * identified by {@code https://host/mcp} publishes at {@code /.well-known/oauth-protected-resource/mcp}.
     * Only that one suffix is answered; any other is a question about a different resource.
     */
    @GetMapping(path = McpResourceServerProperties.METADATA_PATH + "/**",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadataForPath(ServerWebExchange exchange) {
        String requested = exchange.getRequest().getPath().pathWithinApplication().value()
                .substring(McpResourceServerProperties.METADATA_PATH.length());
        if (!normalise(requested).equals(normalise(resourcePath()))) {
            throw new ResponseStatusException(NOT_FOUND, "No protected resource metadata is published for '"
                    + requested + "'. This server's resource identifier is " + resourceIdentifier(exchange)
                    + ".");
        }
        return ResponseEntity.ok(document(exchange));
    }

    private Map<String, Object> document(ServerWebExchange exchange) {
        log.info("Served protected resource metadata to {}, advertising {}.", describeCaller(exchange),
                this.properties.authorizationServers());
        OAuth2ProtectedResourceMetadata.Builder builder = OAuth2ProtectedResourceMetadata.builder()
                .resource(resourceIdentifier(exchange))
                .resourceName(this.properties.resourceName())
                .bearerMethod("header");
        this.properties.authorizationServers().forEach(builder::authorizationServer);
        this.properties.scopesSupported().forEach(builder::scope);

        Map<String, Object> claims = new LinkedHashMap<>(builder.build().getClaims());
        if (this.properties.tokenValidation() == McpResourceServerProperties.TokenValidation.JWE) {
            // In the sealed (JWE) model this server holds the private keys, so it publishes the public halves
            // for the authorization server to encrypt to — the inverse of a signing JWKS.
            claims.put("jwks_uri", baseUrl(exchange) + ResourceEncryptionJwksController.ENC_JWKS_PATH);
        }
        return claims;
    }

    private String baseUrl(ServerWebExchange exchange) {
        String resource = this.properties.resource();
        URI uri = (resource != null) ? URI.create(resource) : exchange.getRequest().getURI();
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    private static String describeCaller(ServerWebExchange exchange) {
        String userAgent = exchange.getRequest().getHeaders().getFirst("User-Agent");
        return (userAgent != null) ? userAgent : "an unidentified client";
    }

    private String resourceIdentifier(ServerWebExchange exchange) {
        String configured = this.properties.resource();
        if (configured != null) {
            return configured;
        }
        URI uri = exchange.getRequest().getURI();
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    private String resourcePath() {
        String configured = this.properties.resource();
        if (configured == null) {
            return "";
        }
        String path = URI.create(configured).getPath();
        return (path == null) ? "" : path;
    }

    private static String normalise(String path) {
        String trimmed = (path == null) ? "" : path.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }
}
