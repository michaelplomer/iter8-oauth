package de.iter8.oauth.as;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import de.iter8.oauth.cimd.ClientAssertionVerifier;
import de.iter8.oauth.cimd.ClientIdMetadata;

/**
 * Publishes this authorization server's RFC 8414 metadata.
 *
 * <p>A client reaches here by following the protected resource metadata from a 401, and what it finds
 * determines whether it can proceed at all. {@code client_id_metadata_document_supported} tells it that it
 * may identify itself with a URL instead of registering, and {@code none} among the token endpoint auth
 * methods tells it a public client is welcome — the two things an upstream identity provider's own metadata
 * does not offer, which is why this server exists.
 */
@RequiredArgsConstructor
@RestController
public class AuthorizationServerMetadataController {

    private final ProviderRegistry providers;

    private final AuthorizationServerUris uris;

    @GetMapping(path = AsPaths.METADATA_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata(ServerWebExchange exchange) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("issuer", this.uris.issuer(exchange));
        document.put("authorization_endpoint", this.uris.absolute(exchange, AsPaths.AUTHORIZATION_PATH));
        document.put("token_endpoint", this.uris.absolute(exchange, AsPaths.TOKEN_PATH));
        document.put("response_types_supported", List.of("code"));
        document.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
        // S256 only: 'plain' protects nothing, since an attacker who can read the challenge can replay it.
        document.put("code_challenge_methods_supported", List.of("S256"));
        // The stronger method first, so a client choosing by order gets the one that proves more, while a
        // client that only has PKCE still finds "none" and connects.
        document.put("token_endpoint_auth_methods_supported",
                List.of(ClientIdMetadata.PRIVATE_KEY_JWT, "none"));
        document.put("token_endpoint_auth_signing_alg_values_supported",
                ClientAssertionVerifier.SIGNING_ALGORITHMS);
        document.put("client_id_metadata_document_supported", true);
        document.put("scopes_supported", this.providers.scopesSupported());
        if (this.providers.hasSignedIdentityProvider()) {
            document.put("jwks_uri", this.uris.absolute(exchange, AsPaths.JWKS_PATH));
        }
        return ResponseEntity.ok(document);
    }
}
