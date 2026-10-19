package de.iter8.oauth.as;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.iter8.oauth.token.InvalidTokenException;
import de.iter8.oauth.token.IssuedToken;
import de.iter8.oauth.token.JweTokenCodec;
import de.iter8.oauth.token.JwsTokenCodec;
import de.iter8.oauth.token.RefreshTokenCodec;
import de.iter8.oauth.token.TokenModel;

/**
 * The token layer: a JWE token seals an upstream credential the client cannot read; a JWS token carries
 * readable identity and nothing secret; and codec selection is fail-closed.
 */
class TokenCodecTests {

    private static final String ISSUER = "https://auth.test";

    private static RSAPublicKey publicKey;
    private static RSAPrivateKey privateKey;

    static {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            publicKey = (RSAPublicKey) pair.getPublic();
            privateKey = (RSAPrivateKey) pair.getPrivate();
        }
        catch (Exception failure) {
            throw new RuntimeException(failure);
        }
    }

    @Test
    void jwe_round_trips_a_sealed_credential() {
        JweTokenCodec codec = new JweTokenCodec(publicKey, privateKey, ISSUER);
        String token = codec.encode("client", "oura", "acct-1", "oura.read",
                "https://oura.mcp.test/mcp", "UPSTREAM-SECRET", null, Instant.now().plusSeconds(300));

        IssuedToken opened = codec.decode(token);
        assertThat(codec.model()).isEqualTo(TokenModel.SEALED_CREDENTIAL);
        assertThat(opened.carriedCredential()).isEqualTo("UPSTREAM-SECRET");
        assertThat(opened.clientId()).isEqualTo("client");
        assertThat(opened.providerId()).isEqualTo("oura");
        assertThat(opened.subject()).isEqualTo("acct-1");
        assertThat(opened.scope()).isEqualTo("oura.read");
        assertThat(opened.resource()).isEqualTo("https://oura.mcp.test/mcp");
    }

    @Test
    void jwe_from_another_keypair_cannot_be_opened() throws Exception {
        JweTokenCodec mine = new JweTokenCodec(publicKey, privateKey, ISSUER);
        KeyPair other = KeyPairGenerator.getInstance("RSA").genKeyPair();
        JweTokenCodec theirs = new JweTokenCodec((RSAPublicKey) other.getPublic(),
                (RSAPrivateKey) other.getPrivate(), ISSUER);

        String token = theirs.encode("c", "oura", "s", null, null, "secret", null,
                Instant.now().plusSeconds(300));
        assertThatThrownBy(() -> mine.decode(token)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void an_expired_token_is_refused() {
        JweTokenCodec codec = new JweTokenCodec(publicKey, privateKey, ISSUER);
        String token = codec.encode("c", "oura", "s", null, null, "secret", null,
                Instant.now().minusSeconds(5));
        assertThatThrownBy(() -> codec.decode(token))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void jws_carries_readable_identity_and_no_secret() {
        JwsTokenCodec codec = new JwsTokenCodec(publicKey, privateKey, ISSUER);
        String token = codec.encode("client", "google-oidc", "me@plomer.info", "whatable.read",
                "https://whatable.mcp.test/mcp", null,
                Map.of("email", "me@plomer.info", "hd", "plomer.info"), Instant.now().plusSeconds(300));

        IssuedToken opened = codec.decode(token);
        assertThat(codec.model()).isEqualTo(TokenModel.SIGNED_IDENTITY);
        assertThat(opened.carriedCredential()).isNull();
        assertThat(opened.subject()).isEqualTo("me@plomer.info");
        assertThat(opened.identityClaims()).containsEntry("email", "me@plomer.info")
                .containsEntry("hd", "plomer.info");

        // The published JWKS is public-only — the signing key never leaves the server.
        assertThat(codec.publicJwks().getKeys()).hasSize(1);
        assertThat(codec.publicJwks().getKeys().get(0).isPrivate()).isFalse();
    }

    @Test
    void refresh_token_round_trips() {
        RefreshTokenCodec codec = new RefreshTokenCodec(null, ISSUER); // generated key for the run
        String token = codec.encode("client", "google-oidc", "me@plomer.info", "whatable.read", null, null,
                Map.of("email", "me@plomer.info"), Instant.now().plusSeconds(300));

        IssuedToken opened = codec.decode(token);
        assertThat(opened.clientId()).isEqualTo("client");
        assertThat(opened.subject()).isEqualTo("me@plomer.info");
        assertThat(opened.identityClaims()).containsEntry("email", "me@plomer.info");
    }

    @Test
    void codec_selection_is_fail_closed() {
        JweTokenCodec jwe = new JweTokenCodec(publicKey, privateKey, ISSUER);
        JwsTokenCodec jws = new JwsTokenCodec(publicKey, privateKey, ISSUER);

        TokenCodecs both = new TokenCodecs(jwe, jws);
        assertThat(both.forModel(TokenModel.SEALED_CREDENTIAL)).isSameAs(jwe);
        assertThat(both.forModel(TokenModel.SIGNED_IDENTITY)).isSameAs(jws);

        // A broker provider must never fall back to signing — that would expose the credential.
        TokenCodecs identityOnly = new TokenCodecs(null, jws);
        assertThatThrownBy(() -> identityOnly.forModel(TokenModel.SEALED_CREDENTIAL))
                .isInstanceOf(IllegalStateException.class);
    }
}
