package de.iter8.oauth.as;

import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Fetches a resource server's public encryption key by discovery: its RFC 9728 protected-resource metadata,
 * then the {@code jwks_uri} that names, then the encryption key ({@code use:"enc"}) in that set.
 *
 * <p>Two checks guard against sealing a credential to the wrong party: the metadata's {@code resource} must be
 * the one asked for, and its {@code authorization_servers} must list this authorization server — a mutual
 * binding, so a resource cannot silently point tokens meant for it at someone else's key.
 */
final class PrmKeyFetcher {

    private final WebClient http;

    private final String authorizationServerIssuer;

    PrmKeyFetcher(WebClient http, String authorizationServerIssuer) {
        this.http = http;
        this.authorizationServerIssuer = authorizationServerIssuer;
    }

    Mono<JWK> fetch(String resource) {
        String metadataUrl = Rfc9728.metadataUrl(resource);
        return this.http.get().uri(metadataUrl).retrieve().bodyToMono(Map.class)
                .flatMap(metadata -> encryptionKey(resource, metadata));
    }

    private Mono<JWK> encryptionKey(String resource, Map<?, ?> metadata) {
        Object declaredResource = metadata.get("resource");
        if (declaredResource != null && !resource.equals(declaredResource)) {
            return Mono.error(new IllegalStateException("Protected resource metadata at " + resource
                    + " identifies itself as " + declaredResource + "; refusing to seal a credential to it."));
        }
        if (this.authorizationServerIssuer != null && !this.authorizationServerIssuer.isBlank()) {
            Object servers = metadata.get("authorization_servers");
            boolean namesThisServer = servers instanceof List<?> list
                    && list.contains(this.authorizationServerIssuer);
            if (!namesThisServer) {
                return Mono.error(new IllegalStateException("Resource " + resource + " does not name this "
                        + "authorization server (" + this.authorizationServerIssuer + ") in its metadata; "
                        + "refusing to seal a credential to it."));
            }
        }
        Object jwksUri = metadata.get("jwks_uri");
        if (jwksUri == null) {
            return Mono.error(new IllegalStateException("Resource " + resource + " publishes no jwks_uri, so "
                    + "no encryption key can be discovered for it."));
        }
        return this.http.get().uri(jwksUri.toString()).retrieve().bodyToMono(String.class)
                .flatMap(json -> selectEncryptionKey(resource, json));
    }

    private static Mono<JWK> selectEncryptionKey(String resource, String jwksJson) {
        try {
            JWKSet set = JWKSet.parse(jwksJson);
            return set.getKeys().stream()
                    .filter(key -> key.getKeyUse() == KeyUse.ENCRYPTION)
                    .findFirst()
                    .map(key -> Mono.just(key.toPublicJWK()))
                    .orElseGet(() -> Mono.error(new IllegalStateException("The key set for " + resource
                            + " has no encryption key (use=enc).")));
        }
        catch (java.text.ParseException failure) {
            return Mono.error(new IllegalStateException("The key set for " + resource + " is not a JWK set.",
                    failure));
        }
    }
}
