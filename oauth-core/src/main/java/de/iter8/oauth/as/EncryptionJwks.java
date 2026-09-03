package de.iter8.oauth.as;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Builds the nimbus JWKs used by the SEALED_CREDENTIAL key model from raw RSA key material, tagging them
 * {@code use:"enc"} and giving each a stable {@code kid} (its RSA thumbprint when none is supplied) so a
 * token's header can name which key it was sealed to.
 */
public final class EncryptionJwks {

    private EncryptionJwks() {
    }

    /**
     * @param publicKey the public half; when {@code null} it is derived from a CRT private key
     * @param privateKey the private half, or {@code null} for a publish-only (authorization-server) key
     * @param kid an explicit key id, or {@code null} to use the RSA thumbprint
     * @return an RSA JWK ({@code use:"enc"}, {@code alg:"RSA-OAEP-256"}) carrying whichever halves were given
     */
    public static RSAKey rsaEncryptionKey(RSAPublicKey publicKey, RSAPrivateKey privateKey, String kid) {
        RSAPublicKey resolvedPublic = (publicKey != null) ? publicKey : derivePublic(privateKey);
        RSAKey.Builder builder = new RSAKey.Builder(resolvedPublic)
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.RSA_OAEP_256);
        if (privateKey != null) {
            builder.privateKey(privateKey);
        }
        RSAKey key = builder.build();
        String resolvedKid = (kid != null && !kid.isBlank()) ? kid : thumbprint(key);
        return new RSAKey.Builder(key).keyID(resolvedKid).build();
    }

    private static RSAPublicKey derivePublic(RSAPrivateKey privateKey) {
        if (!(privateKey instanceof RSAPrivateCrtKey crt)) {
            throw new IllegalStateException("A resource-server encryption key must carry its public half, or "
                    + "be a CRT-form RSA private key it can be derived from (the usual PKCS#8 output). Supply "
                    + "public-key alongside private-key.");
        }
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        }
        catch (Exception failure) {
            throw new IllegalStateException("Could not derive the public half of the encryption key.", failure);
        }
    }

    private static String thumbprint(RSAKey key) {
        try {
            return key.computeThumbprint().toString();
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not compute a key id for the encryption key.", failure);
        }
    }
}
