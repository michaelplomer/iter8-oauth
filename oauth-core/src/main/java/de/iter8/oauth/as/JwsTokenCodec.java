package de.iter8.oauth.as;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

/**
 * The SIGNED_IDENTITY codec: access tokens are signed (RS256) and carry only the authenticated user's
 * identity. Nothing secret travels inside, so — unlike the JWE codec — the token is readable, and resource
 * servers validate it with a standard JWT decoder against the JWKS this codec publishes.
 *
 * <p>This is the whole simplification an identity provider buys: no split keypair, no opaque introspection,
 * no bridged credential. The authorization server signs; every resource server verifies against the public
 * key at {@link #publicJwks()}.
 */
public class JwsTokenCodec implements IssuedTokenCodec {

    private static final String KIND = "access";

    private static final JWSAlgorithm ALGORITHM = JWSAlgorithm.RS256;

    private final RSAKey signingKey;

    private final RSASSASigner signer;

    private final RSASSAVerifier verifier;

    private final String issuer;

    /**
     * @param publicKey the key resource servers verify with, published as JWKS
     * @param privateKey the key this server signs with
     * @param issuer this server's issuer identifier, recorded in and checked on every token
     */
    public JwsTokenCodec(RSAPublicKey publicKey, RSAPrivateKey privateKey, String issuer) {
        try {
            this.signingKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(ALGORITHM)
                    .keyIDFromThumbprint()
                    .build();
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not derive a key id for the signing key.", failure);
        }
        this.signer = new RSASSASigner(privateKey);
        this.verifier = new RSASSAVerifier(publicKey);
        this.issuer = issuer;
    }

    @Override
    public TokenModel model() {
        return TokenModel.SIGNED_IDENTITY;
    }

    /**
     * @return the public half, as a JWK set for resource servers and the JWKS endpoint to verify against
     */
    public JWKSet publicJwks() {
        return new JWKSet(this.signingKey.toPublicJWK());
    }

    @Override
    public String encode(String clientId, String providerId, String subject, String scope, String resource,
            String carriedCredential, Map<String, Object> identityClaims, Instant expiresAt) {
        try {
            SignedJWT token = new SignedJWT(
                    new JWSHeader.Builder(ALGORITHM).keyID(this.signingKey.getKeyID()).build(),
                    TokenClaims.build(KIND, this.issuer, clientId, providerId, subject, scope, resource,
                            null, identityClaims, expiresAt));
            token.sign(this.signer);
            return token.serialize();
        }
        catch (JOSEException failure) {
            throw new IllegalStateException("Could not sign an access token.", failure);
        }
    }

    @Override
    public IssuedToken decode(String value) {
        try {
            SignedJWT token = SignedJWT.parse(value);
            if (!token.verify(this.verifier)) {
                throw new InvalidTokenException("The access token signature does not verify.");
            }
            return TokenClaims.verify(token.getJWTClaimsSet(), KIND, this.issuer);
        }
        catch (ParseException | JOSEException failure) {
            throw new InvalidTokenException("The access token could not be read.");
        }
    }
}
