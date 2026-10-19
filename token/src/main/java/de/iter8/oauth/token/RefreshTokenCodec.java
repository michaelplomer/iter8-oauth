package de.iter8.oauth.token;

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
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Seals and opens refresh tokens.
 *
 * <p>Symmetric, because a refresh token only ever travels between a client and the authorization server that
 * issued it: it is minted here and presented back here. A keypair would add an asymmetric operation to every
 * refresh and separate nothing, since both ends of the journey are the same server. The resource server never
 * sees one and could not open it if it did. Always encrypted (even for identity providers) because it may
 * carry an upstream refresh credential and, either way, is bearer material the client must not read.
 *
 * <p>Each token also carries its own identifier and its family's (see {@link RefreshToken}), so that the
 * server can make tokens single-use and revoke a family when one of its tokens is replayed.
 */
@Slf4j
public class RefreshTokenCodec {

    private static final String KIND = "refresh";

    private static final JWEAlgorithm ALGORITHM = JWEAlgorithm.DIR;

    private static final EncryptionMethod ENCRYPTION = EncryptionMethod.A256GCM;

    /** The claim holding the token's family identifier. */
    private static final String FAMILY = "fam";

    private static final SecureRandom RANDOM = new SecureRandom();

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
     * @param familyId the family this token belongs to: new for a fresh authorization, inherited on refresh
     * @param expiresAt when the token stops being accepted
     * @return the refresh token value
     */
    public String encode(String clientId, String providerId, String subject, String scope, String resource,
            String carriedCredential, Map<String, Object> identityClaims, String familyId,
            Instant expiresAt) {
        if (familyId == null || familyId.isBlank()) {
            throw new IllegalArgumentException("A refresh token needs a family.");
        }
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder(TokenClaims.build(KIND, this.issuer, clientId,
                    providerId, subject, scope, resource, carriedCredential, identityClaims, expiresAt))
                    .jwtID(randomId())
                    .claim(FAMILY, familyId)
                    .build();
            EncryptedJWT token = new EncryptedJWT(new JWEHeader(ALGORITHM, ENCRYPTION), claims);
            token.encrypt(new DirectEncrypter(this.key));
            return token.serialize();
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not encrypt a refresh token.", failure);
        }
    }

    /**
     * @param value a refresh token presented by a client
     * @return what it carries, with its own and its family's identifiers
     * @throws InvalidTokenException when it cannot be opened, is of the wrong kind, has expired, or lacks
     *     its identifiers
     */
    public RefreshToken decode(String value) {
        if (value == null) {
            throw new InvalidTokenException("No refresh token was presented.");
        }
        try {
            EncryptedJWT token = EncryptedJWT.parse(value);
            token.decrypt(new DirectDecrypter(this.key));
            JWTClaimsSet claims = token.getJWTClaimsSet();
            IssuedToken opened = TokenClaims.verify(claims, KIND, this.issuer);
            String tokenId = claims.getJWTID();
            String familyId = claims.getStringClaim(FAMILY);
            if (tokenId == null || familyId == null) {
                throw new InvalidTokenException("The refresh token carries no token or family identifier.");
            }
            return new RefreshToken(tokenId, familyId, opened);
        }
        catch (ParseException | JOSEException failure) {
            throw new InvalidTokenException("The refresh token could not be read.");
        }
    }

    /**
     * @return a new family identifier, for the first refresh token of an authorization
     */
    public static String newFamilyId() {
        return randomId();
    }

    private static String randomId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
