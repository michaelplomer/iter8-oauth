package de.iter8.oauth.as;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import de.iter8.oauth.token.ResourceEncryptionKeyResolver;

/**
 * Discovers each resource's encryption key from its RFC 9728 metadata and caches it. A lookup only reads the
 * cache: when a resource's entry has gone stale, it is still used while a refresh runs in the background.
 * A resource with no entry at all has nothing to seal to, so the token endpoint calls {@link #awaitKey} first,
 * which waits a few seconds for the key to be fetched.
 *
 * <p>Only resources this server is configured to serve are resolvable, which is the trust boundary: a token
 * cannot steer the server into fetching — and sealing to — an arbitrary URL's key.
 */
@Slf4j
public final class DiscoveringResourceEncryptionKeyResolver implements ResourceEncryptionKeyResolver {

    /** How long a token request, or startup, waits for a key that is not cached yet. */
    static final Duration DISCOVERY_TIMEOUT = Duration.ofSeconds(10);

    private record Cached(JWK jwk, Instant refreshAt) {
    }

    private final Set<String> knownResources;

    private final Duration cacheTtl;

    private final Clock clock;

    private final Function<String, Mono<JWK>> fetcher;

    private final Duration discoveryTimeout;

    private final ConcurrentHashMap<String, Cached> cache = new ConcurrentHashMap<>();

    private final ConcurrentHashMap<String, Mono<JWK>> inFlight = new ConcurrentHashMap<>();

    DiscoveringResourceEncryptionKeyResolver(Set<String> knownResources, Duration cacheTtl, Clock clock,
            Function<String, Mono<JWK>> fetcher) {
        this(knownResources, cacheTtl, clock, fetcher, DISCOVERY_TIMEOUT);
    }

    DiscoveringResourceEncryptionKeyResolver(Set<String> knownResources, Duration cacheTtl, Clock clock,
            Function<String, Mono<JWK>> fetcher, Duration discoveryTimeout) {
        this.knownResources = Set.copyOf(knownResources);
        this.cacheTtl = cacheTtl;
        this.clock = clock;
        this.fetcher = fetcher;
        this.discoveryTimeout = discoveryTimeout;
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
     * Fetches and caches the keys for the given resources, waiting briefly on each. Meant to be called once at
     * startup, off the event loop, so the first token request does not have to wait for discovery. A resource
     * that cannot be reached yet is fetched again when a token is first issued for it.
     *
     * @param resources the resources to pre-fetch (typically the brokered ones); unknown ones are skipped
     */
    public void warm(Collection<String> resources) {
        for (String resource : resources) {
            if (!this.knownResources.contains(resource)) {
                continue;
            }
            try {
                // A failed fetch is logged by refresh, so only success and the timeout are logged here.
                JWK jwk = refresh(resource).onErrorResume(failure -> Mono.empty()).block(this.discoveryTimeout);
                if (jwk != null) {
                    log.info("Warmed the encryption key for resource {}.", resource);
                }
            }
            catch (IllegalStateException timeout) {
                log.warn("Timed out warming the encryption key for resource {}. It will be fetched when a token "
                        + "is first issued for it.", resource);
            }
        }
    }

    /**
     * Waits until the resource's key is cached, fetching it first if it is not, so that a token can be sealed
     * to it right after. A stale key is still used, so only a resource with no key at all is waited for.
     * Concurrent callers share one fetch.
     *
     * @param resource the resource a token is about to be sealed for
     * @return a Mono that completes once the key is cached, or once the fetch has failed or taken longer than
     *     the discovery timeout; sealing then finds no key and fails closed
     */
    public Mono<Void> awaitKey(String resource) {
        if (resource == null || !this.knownResources.contains(resource) || this.cache.containsKey(resource)) {
            return Mono.empty();
        }
        return refresh(resource)
                .timeout(this.discoveryTimeout)
                .doOnError(TimeoutException.class, timeout -> log.warn("Timed out waiting for the encryption "
                        + "key for resource {}.", resource))
                .onErrorResume(failure -> Mono.empty())
                .then();
    }

    @Override
    public Optional<JWK> encryptionKeyFor(String resource) {
        if (!this.knownResources.contains(resource)) {
            return Optional.empty();
        }
        Cached cached = this.cache.get(resource);
        if (cached == null || this.clock.instant().isAfter(cached.refreshAt())) {
            refresh(resource);
            cached = this.cache.get(resource); // a synchronous fetcher (or a warm cache) is visible at once
        }
        return Optional.ofNullable((cached == null) ? null : cached.jwk());
    }

    /**
     * Starts fetching the resource's key unless a fetch is already running, and returns that fetch. It runs to
     * the end even when every caller stops waiting for it, so a slow resource is still cached for the next
     * request.
     */
    private Mono<JWK> refresh(String resource) {
        Mono<JWK> running = this.inFlight.get(resource);
        if (running != null) {
            return running;
        }
        Mono<JWK> fetch = this.fetcher.apply(resource)
                .doOnNext(jwk -> this.cache.put(resource,
                        new Cached(jwk, this.clock.instant().plus(this.cacheTtl))))
                .cache();
        running = this.inFlight.putIfAbsent(resource, fetch);
        if (running != null) {
            return running;
        }
        fetch.doFinally(signal -> this.inFlight.remove(resource, fetch))
                .subscribe(jwk -> {
                }, error -> log.warn("Could not discover an encryption key for resource {}: {}", resource,
                        error.getMessage()));
        return fetch;
    }
}
