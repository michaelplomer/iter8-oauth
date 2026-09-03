package de.iter8.oauth.as;

import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;

/**
 * A single, fixed encryption key used for every resource. Backs the single-key {@link JweTokenCodec}
 * constructor — a self-contained deployment or a test that seals to one known key rather than discovering a
 * key per resource.
 */
public final class StaticResourceEncryptionKeyResolver implements ResourceEncryptionKeyResolver {

    private final JWK key;

    /**
     * @param key the public encryption JWK to seal every credential to, or {@code null} for none
     */
    public StaticResourceEncryptionKeyResolver(JWK key) {
        this.key = (key == null) ? null : key.toPublicJWK();
    }

    /**
     * @param publicKey a raw RSA public key, or {@code null}
     * @return a resolver over that key, tagged {@code use:"enc"} with a thumbprint {@code kid}
     */
    public static StaticResourceEncryptionKeyResolver ofRsa(RSAPublicKey publicKey) {
        return new StaticResourceEncryptionKeyResolver(
                (publicKey == null) ? null : EncryptionJwks.rsaEncryptionKey(publicKey, null, null));
    }

    @Override
    public Optional<JWK> encryptionKeyFor(String resource) {
        return Optional.ofNullable(this.key);
    }
}
