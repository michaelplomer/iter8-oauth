package de.iter8.oauth.as;

import java.util.List;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the public keys resource servers verify SIGNED_IDENTITY (JWS) access tokens against.
 *
 * <p>Only meaningful when an identity provider is configured; with none, the set is empty. The private half
 * never leaves this server, so nothing secret is exposed here — that is the whole point of the JWS model.
 */
@RequiredArgsConstructor
@RestController
public class JwksController {

    private final TokenCodecs codecs;

    @GetMapping(path = AsPaths.JWKS_PATH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        if (this.codecs.jws() == null) {
            return ResponseEntity.ok(Map.of("keys", List.of()));
        }
        // toJSONObject() on a public JWK set emits only public parameters.
        return ResponseEntity.ok(this.codecs.jws().publicJwks().toJSONObject());
    }
}
