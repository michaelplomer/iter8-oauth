package de.iter8.oauth.as;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import de.iter8.oauth.token.ResourceEncryptionKeyResolver;

/**
 * Discovers each resource's encryption key from its RFC 9728 metadata and caches it. Encryption stays
 * synchronous and non-blocking: a lookup reads the cache and, when a resource is unknown or its entry has
 * gone stale, kicks off a background refresh rather than waiting on the network. The first seal for a
 * cold resource therefore finds nothing here and fails closed; the discovered key is used once it lands (keys
 * change rarely, so the one-time miss is acceptable).
 *
 * <p>Only resources this server is configured to serve are resolvable, which is the trust boundary: a token
 * cannot steer the server into fetching — and sealing to — an arbitrary URL's key.
 */
@Slf4j
public final class DiscoveringResourceEncryptionKeyResolver implements ResourceEncryptionKeyResolver {

    private record Cached(JWK jwk, Instant refreshAt) {
    }

    private final Set<String> knownResources;

    private final Duration cacheTtl;

    private final Clock clock;

    private final Function<String, Mono<JWK>> fetcher;

    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();

    DiscoveringResourceEncryptionKeyResolver(Set<String> knownResources, Duration cacheTtl, Clock clock,
            Function<String, Mono<JWK>> fetcher) {
        this.knownResources = Set.copyOf(knownResources);
        this.cacheTtl = cacheTtl;
        this.clock = clock;
        this.fetcher = fetcher;
    }

    /**
     * @param http the client used to fetch metadata and key sets
     * @param knownResources the resources this server serves — the only ones a key is fetched for
     * @param authorizationServerIssuer this server's issuer, checked against each resource's metadata
     * @param cacheTtl how long a discovered key is used before a background refresh
     * @param clock the time source
     */
    public static DiscoveringResourceEncryptionKeyResolver over(WebClient http, Set<String> knownResources,
            String authorizationServerIssuer, Duration cacheTtl, Clock clock) {
        return new DiscoveringResourceEncryptionKeyResolver(knownResources, cacheTtl, clock,
                new PrmKeyFetcher(http, authorizationServerIssuer)::fetch);
    }

    /**
     * Eagerly fetches and caches the keys for the given resources, blocking briefly on each. Meant to be
     * called once at startup (off the event loop — e.g. from an {@code ApplicationRunner}) so the first token
     * a cold instance seals finds a warm cache rather than the empty result the non-blocking path returns.
     * Failures are logged, not thrown: a resource that is momentarily unreachable at boot is retried lazily
     * on first use.
     *
     * @param resources the resources to pre-fetch (typically the brokered ones); unknown ones are skipped
     */
    public void warm(Collection<String> resources) {
        for (String resource : resources) {
            if (!this.knownResources.contains(resource)) {
                continue;
            }
            try {
                JWK jwk = this.fetcher.apply(resource).block(Duration.ofSeconds(10));
                if (jwk != null) {
                    this.cache.put(resource, new Cached(jwk, this.clock.instant().plus(this.cacheTtl)));
                    log.info("Warmed the encryption key for resource {}.", resource);
                }
            }
            catch (RuntimeException failure) {
                log.warn("Could not warm the encryption key for resource {}: {}. It will be retried on first "
                        + "use.", resource, failure.getMessage());
            }
        }
    }

    @Override
    public Optional<JWK> encryptionKeyFor(String resource) {
        if (!this.knownResources.contains(resource)) {
            return Optional.empty();
        }
        Cached cached = this.cache.get(resource);
        if (cached == null || this.clock.instant().isAfter(cached.refreshAt())) {
            triggerRefresh(resource);
            cached = this.cache.get(resource); // a synchronous fetcher (or a warm cache) is visible at once
        }
        return Optional.ofNullable((cached == null) ? null : cached.jwk());
    }

    private void triggerRefresh(String resource) {
        if (!this.inFlight.add(resource)) {
            return; // a refresh for this resource is already running
        }
        this.fetcher.apply(resource)
                .doFinally(signal -> this.inFlight.remove(resource))
                .subscribe(
                        jwk -> this.cache.put(resource, new Cached(jwk, this.clock.instant().plus(this.cacheTtl))),
                        error -> log.warn("Could not discover an encryption key for resource {}: {}", resource,
                                error.getMessage()));
    }
}
