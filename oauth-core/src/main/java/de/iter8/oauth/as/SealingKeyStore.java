package de.iter8.oauth.as;

import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * Resource-server side of the SEALED_CREDENTIAL key model: holds the private halves that open credentials
 * sealed to this resource, and the public halves it publishes for authorization servers to seal to.
 *
 * <p>Rotation is expressed here: the store publishes the current encryption key (and, briefly, a retiring
 * one) via {@link #publicJwks()}, and keeps the private half of a retired key until the tokens sealed to it
 * have expired, selecting it by the {@code kid} in the token's header.
 */
public interface SealingKeyStore {

    /**
     * @param kid the {@code kid} from an inbound token's JWE header, or {@code null} when it carries none
     * @return the private JWK that opens it, or empty when no key matches (rotated out, or never held)
     */
    Optional<JWK> decryptionKey(String kid);

    /**
     * @return the public halves to publish, each {@code use:"enc"} with a {@code kid}; never {@code null}
     */
    JWKSet publicJwks();
}
