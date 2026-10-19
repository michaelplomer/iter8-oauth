package de.iter8.oauth.token;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.EncryptedJWT;

/**
 * The SEALED_CREDENTIAL codec: access tokens are encrypted to a public key whose private half belongs to the
 * resource server the token is for.
 *
 * <p>Encrypted rather than signed, because an upstream credential travels inside. A signed token is readable
 * by whoever holds it, which would hand the client the upstream credential and let it bypass this server —
 * something the MCP specification forbids outright. The authorization server issues with the public key and
 * cannot read the token afterwards; the resource server holds the private key and is the only thing that can.
 *
 * <p>The key is resolved <em>per resource</em>: the {@link ResourceEncryptionKeyResolver} yields the audience's
 * current encryption key on the issuing side, and the {@link SealingKeyStore} selects the private half by the
 * header's {@code kid} on the opening side. This is what makes a token openable by exactly one audience, and
 * what lets several brokered resources each get credentials only they can read.
 */
public class JweTokenCodec implements IssuedTokenCodec {

    private static final String KIND = "access";

    private final ResourceEncryptionKeyResolver keyResolver;

    private final SealingKeyStore keyStore;

    private final String issuer;

    /**
     * @param keyResolver resolves the audience's encryption key when issuing, or {@code null} where this
     *     deployment only opens tokens
     * @param keyStore selects the private key when opening, or {@code null} where this deployment only issues
     * @param issuer this server's issuer identifier, recorded in and checked on every token
     */
    public JweTokenCodec(ResourceEncryptionKeyResolver keyResolver, SealingKeyStore keyStore, String issuer) {
        this.keyResolver = keyResolver;
        this.keyStore = keyStore;
        this.issuer = issuer;
    }

    /**
     * The single-key form: one static key for every resource, its private half opening every token. What a
     * pre-discovery deployment and the tests use. Verifies the two halves are a pair at construction, since
     * two unrelated but valid keys look well formed and the mismatch would otherwise show up only as tokens
     * that issue cleanly and then cannot be read.
     *
     * @param publicKey used to issue tokens, or {@code null} where this deployment only reads them
     * @param privateKey used to open tokens, or {@code null} where this deployment only issues them
     * @param issuer this server's issuer identifier
     */
    public JweTokenCodec(RSAPublicKey publicKey, RSAPrivateKey privateKey, String issuer) {
        this(StaticResourceEncryptionKeyResolver.ofRsa(publicKey),
                (privateKey == null) ? null : SingleKeySealingKeyStore.ofRsa(publicKey, privateKey), issuer);
        if (publicKey != null && privateKey != null) {
            assertKeysAgree();
        }
    }

    @Override
    public TokenModel model() {
        return TokenModel.SEALED_CREDENTIAL;
    }

    private void assertKeysAgree() {
        String probe = "key-pair-check";
        try {
            IssuedToken opened = decode(encode(probe, probe, probe, null, probe, probe, null,
                    Instant.now().plusSeconds(60)));
            if (!probe.equals(opened.carriedCredential())) {
                throw new IllegalStateException("round trip returned something else");
            }
        }
        catch (RuntimeException failure) {
            throw new IllegalStateException("The configured access token keys are not a pair: a token "
                    + "encrypted with the public key could not be read with the private key. Generate both "
                    + "halves from one key: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
                    + "-out key.pem", failure);
        }
    }

    @Override
    public String encode(String clientId, String providerId, String subject, String scope, String resource,
            String carriedCredential, Map<String, Object> identityClaims, Instant expiresAt) {
        if (this.keyResolver == null) {
            throw new IllegalStateException("This server has no encryption key resolver, so it cannot issue "
                    + "SEALED_CREDENTIAL access tokens.");
        }
        JWK key = this.keyResolver.encryptionKeyFor(resource)
                .orElseThrow(() -> new IllegalStateException("No encryption key is available for resource '"
                        + resource + "', so a credential cannot be sealed for it. The resource must publish an "
                        + "encryption key (RFC 9728 jwks_uri), or a static key must be configured."));
        try {
            JWEHeader header = new JWEHeader.Builder(JweCrypto.keyManagementAlgorithm(key),
                    JweCrypto.CONTENT_ENCRYPTION).keyID(key.getKeyID()).build();
            EncryptedJWT token = new EncryptedJWT(header, TokenClaims.build(KIND, this.issuer, clientId,
                    providerId, subject, scope, resource, carriedCredential, identityClaims, expiresAt));
            token.encrypt(JweCrypto.encrypter(key));
            return token.serialize();
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not encrypt an access token.", failure);
        }
    }

    @Override
    public IssuedToken decode(String value) {
        if (this.keyStore == null) {
            throw new IllegalStateException("This server has no access token key store, so it cannot read "
                    + "SEALED_CREDENTIAL access tokens.");
        }
        try {
            EncryptedJWT token = EncryptedJWT.parse(value);
            JWK key = this.keyStore.decryptionKey(token.getHeader().getKeyID())
                    .orElseThrow(() -> new InvalidTokenException("The access token was sealed to a key this "
                            + "server does not hold."));
            token.decrypt(JweCrypto.decrypter(key));
            return TokenClaims.verify(token.getJWTClaimsSet(), KIND, this.issuer);
        }
        catch (InvalidTokenException failure) {
            throw failure;
        }
        catch (ParseException | JOSEException failure) {
            // Anything unreadable was not issued to a key this server holds.
            throw new InvalidTokenException("The access token could not be read.");
        }
    }
}
