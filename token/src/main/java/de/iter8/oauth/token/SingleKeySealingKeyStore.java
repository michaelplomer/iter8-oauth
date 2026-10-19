package de.iter8.oauth.token;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * A sealing key store holding exactly one encryption key, opening every inbound token with it regardless of
 * the {@code kid} the token names. The single-key, pre-rotation arrangement, and what the back-compatible
 * {@link JweTokenCodec} constructor builds. A token sealed to some other key simply fails to decrypt, which
 * is caught as an invalid token.
 */
public final class SingleKeySealingKeyStore implements SealingKeyStore {

    private final JWK key;

    /**
     * @param key the private encryption JWK, or {@code null} where this deployment only issues tokens
     */
    public SingleKeySealingKeyStore(JWK key) {
        this.key = key;
    }

    /**
     * @param publicKey the public half, or {@code null} to derive it from a CRT private key
     * @param privateKey the private half
     */
    public static SingleKeySealingKeyStore ofRsa(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        return new SingleKeySealingKeyStore(
                (privateKey == null) ? null : EncryptionJwks.rsaEncryptionKey(publicKey, privateKey, null));
    }

    @Override
    public Optional<JWK> decryptionKey(String kid) {
        return Optional.ofNullable(this.key);
    }

    @Override
    public JWKSet publicJwks() {
        return (this.key == null) ? new JWKSet() : new JWKSet(this.key.toPublicJWK());
    }
}
