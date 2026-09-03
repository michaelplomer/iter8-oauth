package de.iter8.oauth.as;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The per-resource SEALED_CREDENTIAL key model: a token is sealed to a key a resource server publishes and
 * opened by that server via the {@code kid}; a token sealed to a key the server does not hold is refused; and
 * the discovering resolver only resolves resources it is configured for, then caches.
 */
class ResourceEncryptionKeyTests {

    private static final String ISSUER = "https://auth.test";

    private static RSAKeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new RSAKeyPair((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate());
        }
        catch (Exception failure) {
            throw new RuntimeException(failure);
        }
    }

    private record RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
    }

    @Test
    void a_token_is_sealed_to_the_published_key_and_opened_by_kid() {
        RSAKeyPair rs = keyPair();
        // Resource-server side: hold the private key, publish the public half.
        JWK privateJwk = EncryptionJwks.rsaEncryptionKey(rs.publicKey(), rs.privateKey(), null);
        KeyedSealingKeyStore store = new KeyedSealingKeyStore(List.of(privateJwk));
        JWK publishedPublic = store.publicJwks().getKeys().get(0);
        assertThat(publishedPublic.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        assertThat(publishedPublic.isPrivate()).isFalse();

        // Authorization-server side: seal to the published public key.
        JweTokenCodec asCodec = new JweTokenCodec(new StaticResourceEncryptionKeyResolver(publishedPublic),
                null, ISSUER);
        String token = asCodec.encode("client", "oura", "acct-1", "oura.read", "https://oura.test/mcp",
                "UPSTREAM-SECRET", null, Instant.now().plusSeconds(300));

        // Resource-server side: open it, selecting the private key by the header kid.
        JweTokenCodec rsCodec = new JweTokenCodec((ResourceEncryptionKeyResolver) null, store, ISSUER);
        IssuedToken opened = rsCodec.decode(token);
        assertThat(opened.carriedCredential()).isEqualTo("UPSTREAM-SECRET");
        assertThat(opened.resource()).isEqualTo("https://oura.test/mcp");
    }

    @Test
    void a_token_sealed_to_a_key_the_server_does_not_hold_is_refused() {
        RSAKeyPair held = keyPair();
        RSAKeyPair other = keyPair();
        KeyedSealingKeyStore store = new KeyedSealingKeyStore(
                List.of(EncryptionJwks.rsaEncryptionKey(held.publicKey(), held.privateKey(), null)));

        JWK otherPublic = EncryptionJwks.rsaEncryptionKey(other.publicKey(), null, null).toPublicJWK();
        JweTokenCodec asCodec = new JweTokenCodec(new StaticResourceEncryptionKeyResolver(otherPublic), null,
                ISSUER);
        String token = asCodec.encode("c", "oura", "s", null, "https://oura.test/mcp", "secret", null,
                Instant.now().plusSeconds(300));

        JweTokenCodec rsCodec = new JweTokenCodec((ResourceEncryptionKeyResolver) null, store, ISSUER);
        assertThatThrownBy(() -> rsCodec.decode(token)).isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void discovery_resolves_only_known_resources_and_caches() {
        RSAKeyPair rs = keyPair();
        JWK published = EncryptionJwks.rsaEncryptionKey(rs.publicKey(), null, null).toPublicJWK();
        String resource = "https://oura.test/mcp";

        DiscoveringResourceEncryptionKeyResolver resolver = new DiscoveringResourceEncryptionKeyResolver(
                Set.of(resource), Duration.ofMinutes(15), Clock.systemUTC(), r -> Mono.just(published));

        // A resource this server is not configured for is never fetched.
        assertThat(resolver.encryptionKeyFor("https://elsewhere.test/mcp")).isEmpty();

        // A known resource is fetched (synchronously here) and then served from cache.
        assertThat(resolver.encryptionKeyFor(resource)).contains(published);
        assertThat(resolver.encryptionKeyFor(resource)).contains(published);
    }
}
