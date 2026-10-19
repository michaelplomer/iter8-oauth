package de.iter8.oauth.cimd;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Verifies a {@code private_key_jwt} client assertion (RFC 7523) against the keys the client publishes.
 *
 * <p>This is the counterpart of the client identifier itself. A client names itself with a URL, and that
 * document points at its keys, so a client can prove who it is without anything having been agreed here in
 * advance — no registration, no shared secret, nothing to leak from this server's side. It is strictly
 * stronger than a public client, which proves only that it is the same party that started the flow.
 *
 * <p>No replay cache. A {@code jti} store would be server state, which this design does not keep, and it
 * would buy little: an assertion is only useful alongside an authorization code, a code is single use, and
 * redeeming one also requires the PKCE verifier for the challenge it was issued against. A replayed
 * assertion on its own redeems nothing. The lifetime cap below is what bounds the window.
 */
@Slf4j
public class ClientAssertionVerifier {

    /**
     * The assertion type RFC 7523 defines. A client that sends anything else is not doing this.
     */
    public static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * Signature algorithms accepted, taken from the assertion's own header. Restricting these is what
     * stops a client choosing something weak, and excluding {@code none} is what stops it choosing nothing.
     */
    public static final List<String> SIGNING_ALGORITHMS = List.of("RS256", "RS384", "RS512",
            "ES256", "ES384", "ES512", "PS256", "PS384", "PS512");

    /**
     * The furthest ahead an assertion's expiry may be. RFC 7523 leaves the lifetime to the server, and a
     * short one is what limits the value of capturing an assertion in the absence of a replay cache.
     */
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(5);

    /**
     * Tolerance for clock differences between this server and the client.
     */
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);


    private final ClientIdMetadataResolver resolver;

    private final Duration cacheTtl;

    /** How many client key sets are kept. Their URLs are chosen by clients, so this has to be bounded. */
    static final int MAX_CACHED_KEY_SETS = 1_000;

    private final ExpiringCache<JWKSet> keys = new ExpiringCache<>(MAX_CACHED_KEY_SETS);

    /**
     * @param resolver used to fetch the client's key set under the same rules as its metadata document
     * @param cacheTtl how long a fetched key set is reused
     */
    public ClientAssertionVerifier(ClientIdMetadataResolver resolver, Duration cacheTtl) {
        this.resolver = resolver;
        this.cacheTtl = cacheTtl;
    }

    /**
     * Verifies that an assertion was signed by the client it claims to come from, and is addressed to this
     * server.
     *
     * @param client the client's metadata, which says where its keys are
     * @param assertionType the {@code client_assertion_type} presented
     * @param assertion the {@code client_assertion} presented
     * @param audiences the values this server accepts in {@code aud}: its issuer and its token endpoint
     * @return an empty result when the assertion is good, an error carrying the reason when it is not
     */
    public Mono<Void> verify(ClientIdMetadata client, String assertionType, String assertion,
            Set<String> audiences) {
        // Absence first: a client that sent nothing at all is told what is missing, rather than being
        // told its absent assertion_type has the wrong value.
        if (assertion == null || assertion.isBlank()) {
            return Mono.error(new ClientAssertionException("This client declares "
                    + "token_endpoint_auth_method 'private_key_jwt', so client_assertion is required."));
        }
        if (!ASSERTION_TYPE.equals(assertionType)) {
            return Mono.error(new ClientAssertionException("client_assertion_type must be "
                    + ASSERTION_TYPE + "."));
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(assertion);
        }
        catch (ParseException failure) {
            return Mono.error(new ClientAssertionException("The client_assertion is not a signed JWT."));
        }
        String algorithm = String.valueOf(jwt.getHeader().getAlgorithm());
        if (!SIGNING_ALGORITHMS.contains(algorithm)) {
            return Mono.error(new ClientAssertionException("The client_assertion is signed with '"
                    + algorithm + "'; this server accepts " + String.join(", ", SIGNING_ALGORITHMS) + "."));
        }

        return keySet(client)
                .flatMap(keySet -> Mono.fromCallable(() -> {
                    verifySignatureAndClaims(jwt, keySet, client.clientId(), audiences, algorithm);
                    return true;
                }))
                .then();
    }

    private void verifySignatureAndClaims(SignedJWT jwt, JWKSet keySet, String clientId,
            Set<String> audiences, String algorithm) {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.parse(algorithm),
                new ImmutableJWKSet<>(keySet)));
        // Claims are checked below rather than by a verifier, so that each failure can say which one.
        processor.setJWTClaimsSetAwareJWSKeySelector(null);
        processor.setJWTClaimsSetVerifier((claims, context) -> { });

        JWTClaimsSet claims;
        try {
            claims = processor.process(jwt, null);
        }
        catch (Exception failure) {
            throw new ClientAssertionException("The client_assertion signature does not verify against "
                    + "the keys at the client's jwks_uri: " + failure.getMessage());
        }

        // iss and sub are both the client id: the assertion says who signed it and who it is about, and
        // for client authentication those are the same party. Accepting a mismatch would let one client
        // authenticate as another using its own key.
        if (!clientId.equals(claims.getIssuer())) {
            throw new ClientAssertionException("The client_assertion 'iss' is '" + claims.getIssuer()
                    + "', which is not the client it is presented for.");
        }
        if (!clientId.equals(claims.getSubject())) {
            throw new ClientAssertionException("The client_assertion 'sub' is '" + claims.getSubject()
                    + "', which is not the client it is presented for.");
        }
        List<String> audience = claims.getAudience();
        if (audience == null || audience.stream().noneMatch(audiences::contains)) {
            // Without this an assertion captured by another server could be replayed here.
            throw new ClientAssertionException("The client_assertion 'aud' is " + audience
                    + ", which does not name this server. It accepts " + audiences + ".");
        }
        Date expiry = claims.getExpirationTime();
        if (expiry == null) {
            throw new ClientAssertionException("The client_assertion has no 'exp'.");
        }
        Instant now = Instant.now();
        if (expiry.toInstant().isBefore(now.minus(CLOCK_SKEW))) {
            throw new ClientAssertionException("The client_assertion expired at " + expiry.toInstant()
                    + ".");
        }
        if (expiry.toInstant().isAfter(now.plus(MAX_LIFETIME).plus(CLOCK_SKEW))) {
            throw new ClientAssertionException("The client_assertion expires at " + expiry.toInstant()
                    + ", more than " + MAX_LIFETIME.toMinutes() + " minutes ahead. This server keeps no "
                    + "replay cache, so a long lived assertion is refused rather than trusted.");
        }
        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null && notBefore.toInstant().isAfter(now.plus(CLOCK_SKEW))) {
            throw new ClientAssertionException("The client_assertion is not valid until "
                    + notBefore.toInstant() + ".");
        }
    }

    private Mono<JWKSet> keySet(ClientIdMetadata client) {
        JWKSet cached = this.keys.getFresh(client.jwksUri());
        if (cached != null) {
            return Mono.just(cached);
        }
        return this.resolver.fetchFromClientUrl(client.jwksUri(), "jwks_uri")
                .map(body -> {
                    JWKSet parsed;
                    try {
                        parsed = JWKSet.parse(body);
                    }
                    catch (ParseException failure) {
                        throw new ClientAssertionException(
                                "The document at the client's jwks_uri is not a JWK set.");
                    }
                    if (parsed.getKeys().stream().noneMatch(ClientAssertionVerifier::isUsable)) {
                        throw new ClientAssertionException(
                                "The client's jwks_uri publishes no key this server can verify with.");
                    }
                    this.keys.put(client.jwksUri(), parsed, Instant.now().plus(this.cacheTtl));
                    return parsed;
                });
    }

    private static boolean isUsable(JWK key) {
        return KeyType.RSA.equals(key.getKeyType()) || KeyType.EC.equals(key.getKeyType());
    }
}
