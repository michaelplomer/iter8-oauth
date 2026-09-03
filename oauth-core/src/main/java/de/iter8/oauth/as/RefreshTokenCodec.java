package de.iter8.oauth.as;

import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;

/**
 * Seals and opens refresh tokens.
 *
 * <p>Symmetric, because a refresh token only ever travels between a client and the authorization server that
 * issued it: it is minted here and presented back here. A keypair would add an asymmetric operation to every
 * refresh and separate nothing, since both ends of the journey are the same server. The resource server never
 * sees one and could not open it if it did. Always encrypted (even for identity providers) because it may
 * carry an upstream refresh credential and, either way, is bearer material the client must not read.
 */
@Slf4j
public class RefreshTokenCodec {

    private static final String KIND = "refresh";

    private static final JWEAlgorithm ALGORITHM = JWEAlgorithm.DIR;

    private static final EncryptionMethod ENCRYPTION = EncryptionMethod.A256GCM;

    private final SecretKeySpec key;

    private final String issuer;

    /**
     * @param encodedKey base64 of a 32 byte key, or {@code null} to generate one for this run
     * @param issuer this server's issuer identifier, recorded in and checked on every token
     */
    public RefreshTokenCodec(String encodedKey, String issuer) {
        this.key = new SecretKeySpec(resolveKey(encodedKey), "AES");
        this.issuer = issuer;
    }

    private static byte[] resolveKey(String encodedKey) {
        if (encodedKey != null && !encodedKey.isBlank()) {
            byte[] decoded = Base64.getDecoder().decode(encodedKey.trim());
            if (decoded.length != 32) {
                throw new IllegalStateException("The refresh token key must be 32 bytes, base64 encoded; "
                        + "got " + decoded.length + " bytes. Generate one with: head -c 32 /dev/urandom "
                        + "| base64");
            }
            return decoded;
        }
        byte[] generated = new byte[32];
        new SecureRandom().nextBytes(generated);
        log.warn("No refresh token key is configured, so one was generated for this run. Every issued "
                + "refresh token stops working when this server restarts. Generate one with: head -c 32 "
                + "/dev/urandom | base64");
        return generated;
    }

    /**
     * @param clientId the client the token is issued to
     * @param providerId the upstream provider it stands for
     * @param subject the stable user identity
     * @param scope the scopes granted, or {@code null}
     * @param resource the resource the eventual access token will be for
     * @param carriedCredential the upstream refresh credential to seal (broker), or {@code null}
     * @param identityClaims identity claims to carry (identity provider), or {@code null}
     * @param expiresAt when the token stops being accepted
     * @return the refresh token value
     */
    public String encode(String clientId, String providerId, String subject, String scope, String resource,
            String carriedCredential, Map<String, Object> identityClaims, Instant expiresAt) {
        try {
            EncryptedJWT token = new EncryptedJWT(new JWEHeader(ALGORITHM, ENCRYPTION),
                    TokenClaims.build(KIND, this.issuer, clientId, providerId, subject, scope, resource,
                            carriedCredential, identityClaims, expiresAt));
            token.encrypt(new DirectEncrypter(this.key));
            return token.serialize();
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not encrypt a refresh token.", failure);
        }
    }

    /**
     * @param value a refresh token presented by a client
     * @return what it carries
     * @throws InvalidTokenException when it cannot be opened, is of the wrong kind, or has expired
     */
    public IssuedToken decode(String value) {
        if (value == null) {
            throw new InvalidTokenException("No refresh token was presented.");
        }
        try {
            EncryptedJWT token = EncryptedJWT.parse(value);
            token.decrypt(new DirectDecrypter(this.key));
            return TokenClaims.verify(token.getJWTClaimsSet(), KIND, this.issuer);
        }
        catch (ParseException | JOSEException failure) {
            throw new InvalidTokenException("The refresh token could not be read.");
        }
    }
}
