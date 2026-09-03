package de.iter8.oauth.as;

import lombok.extern.slf4j.Slf4j;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * An RSA keypair for sealing issued tokens, with each half separable.
 *
 * <p>For the JWE (SEALED_CREDENTIAL) model the halves live in different places: the authorization server
 * holds the public key and encrypts to it, and the resource server holds the private key and is the only
 * thing that can open a token. That is what lets the two be pulled into separate services — the AS can mint
 * tokens it cannot itself read. For the JWS (SIGNED_IDENTITY) model the AS signs with the private key and
 * publishes the public key as JWKS for resource servers to verify against.
 *
 * <p>When no keys are configured, one throwaway pair is generated for the run, so a first start works and
 * every issued token dies with the process.
 */
@Slf4j
public class TokenKeys {

    private final RSAPublicKey publicKey;

    private final RSAPrivateKey privateKey;

    /**
     * @param encodedPublicKey base64 of an X.509 encoded RSA public key, or {@code null}
     * @param encodedPrivateKey base64 of a PKCS#8 encoded RSA private key, or {@code null}
     */
    public TokenKeys(String encodedPublicKey, String encodedPrivateKey) {
        boolean hasPublic = hasText(encodedPublicKey);
        boolean hasPrivate = hasText(encodedPrivateKey);
        if (!hasPublic && !hasPrivate) {
            KeyPair generated = generateKeyPair();
            this.publicKey = (RSAPublicKey) generated.getPublic();
            this.privateKey = (RSAPrivateKey) generated.getPrivate();
            log.warn("No token keypair is configured, so one was generated for this run. Every issued "
                    + "access token becomes unreadable when this server restarts. Configure a lasting pair.");
        }
        else {
            // Either half alone is legitimate: it is what a split JWE deployment looks like, where the
            // authorization server holds only the public key and the resource server only the private one.
            this.publicKey = hasPublic ? readPublicKey(encodedPublicKey) : null;
            this.privateKey = hasPrivate ? readPrivateKey(encodedPrivateKey) : null;
        }
    }

    /**
     * @return the public key, or {@code null} where this deployment only reads JWE tokens
     */
    public RSAPublicKey publicKey() {
        return this.publicKey;
    }

    /**
     * @return the private key, or {@code null} where this deployment only issues JWE tokens
     */
    public RSAPrivateKey privateKey() {
        return this.privateKey;
    }

    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        }
        catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("RSA is required of every JVM", failure);
        }
    }

    private static RSAPublicKey readPublicKey(String encoded) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(decode(encoded, "PUBLIC KEY")));
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | RuntimeException failure) {
            throw new IllegalStateException("The configured token public key is not a base64 X.509 encoded "
                    + "RSA public key. Generate a pair with: openssl genpkey -algorithm RSA -pkeyopt "
                    + "rsa_keygen_bits:2048 -out key.pem && openssl pkey -in key.pem -pubout -outform DER "
                    + "| base64", failure);
        }
    }

    private static RSAPrivateKey readPrivateKey(String encoded) {
        try {
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(decode(encoded, "PRIVATE KEY")));
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | RuntimeException failure) {
            throw new IllegalStateException("The configured token private key is not a base64 PKCS#8 "
                    + "encoded RSA private key. Produce one with: openssl pkey -in key.pem -outform DER "
                    + "| base64", failure);
        }
    }

    /**
     * Accepts either raw base64 or a PEM block, since both are what a person has to hand.
     */
    private static byte[] decode(String value, String pemLabel) {
        String cleaned = value.replace("-----BEGIN " + pemLabel + "-----", "")
                .replace("-----END " + pemLabel + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(cleaned);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
