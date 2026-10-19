package de.iter8.oauth.token;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Turns a published encryption JWK into the JOSE primitives needed to seal and open a token. RSA
 * (RSA-OAEP-256) and EC (ECDH-ES) keys are both understood, so a resource server may publish either; the
 * content is always AES-256-GCM.
 */
final class JweCrypto {

    private JweCrypto() {
    }

    static final EncryptionMethod CONTENT_ENCRYPTION = EncryptionMethod.A256GCM;

    /**
     * @return the key-management algorithm to name in the header — the key's own {@code alg} when it declares
     *     one, otherwise the standard choice for its type
     */
    static JWEAlgorithm keyManagementAlgorithm(JWK key) {
        if (key.getAlgorithm() != null) {
            return JWEAlgorithm.parse(key.getAlgorithm().getName());
        }
        return switch (key.getKeyType().getValue()) {
            case "RSA" -> JWEAlgorithm.RSA_OAEP_256;
            case "EC" -> JWEAlgorithm.ECDH_ES_A256KW;
            default -> throw new IllegalArgumentException("Unsupported encryption key type: " + key.getKeyType());
        };
    }

    static JWEEncrypter encrypter(JWK key) {
        try {
            if (key instanceof RSAKey rsa) {
                return new RSAEncrypter(rsa);
            }
            if (key instanceof ECKey ec) {
                return new ECDHEncrypter(ec);
            }
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not build an encrypter from the resource key.", failure);
        }
        throw new IllegalArgumentException("Unsupported encryption key type: " + key.getKeyType());
    }

    static JWEDecrypter decrypter(JWK key) {
        try {
            if (key instanceof RSAKey rsa) {
                return new RSADecrypter(rsa);
            }
            if (key instanceof ECKey ec) {
                return new ECDHDecrypter(ec);
            }
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not build a decrypter from the resource key.", failure);
        }
        throw new IllegalArgumentException("Unsupported decryption key type: " + key.getKeyType());
    }
}
