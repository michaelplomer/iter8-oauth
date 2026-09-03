package de.iter8.oauth.rs;

import java.util.Map;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import de.iter8.oauth.as.SealingKeyStore;

/**
 * Publishes the public halves of this resource server's sealing keys, so an authorization server can encrypt
 * a SEALED_CREDENTIAL token that only this server can open. The mirror of the AS's own JWKS: there the AS
 * publishes signing keys to be verified against; here the resource server publishes encryption keys to be
 * sealed to. Nothing secret is exposed — only public parameters — which is the whole point of the model.
 *
 * <p>Advertised through this resource's protected-resource metadata ({@code jwks_uri}) and reachable without a
 * token (it lives under {@code /.well-known/**}), because the AS reads it before any token exists.
 */
@RequiredArgsConstructor
@RestController
@ConditionalOnProperty(prefix = "iter8.resource-server", name = "enabled", havingValue = "true")
@ConditionalOnProperty(prefix = "iter8.resource-server", name = "token-validation", havingValue = "jwe")
public class ResourceEncryptionJwksController {

    /** Where the public sealing keys are published; named by this resource's metadata {@code jwks_uri}. */
    public static final String ENC_JWKS_PATH = "/.well-known/jwe-encryption-keys.json";

    private final SealingKeyStore keyStore;

    @GetMapping(path = ENC_JWKS_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        // toJSONObject() on a public JWK set emits only public parameters.
        return ResponseEntity.ok(this.keyStore.publicJwks().toJSONObject());
    }
}
