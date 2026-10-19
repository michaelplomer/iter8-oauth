package de.iter8.oauth.cimd;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBufferLimitException;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.json.JsonMapper;

/**
 * Turns a Client Identifier URL into the client's metadata, by fetching the document it points at.
 *
 * <p>This is what lets an MCP client use this authorization server without registering: it identifies itself
 * with a URL it controls, and the document there says what it is and where it may be redirected. No shared
 * secret is created, and nothing has to be provisioned here in advance.
 *
 * <p>The fetch is the dangerous part, because the URL comes from an unauthenticated caller. Four things keep
 * it honest, all of them required by the specification:
 *
 * <ul>
 * <li>the URL is validated before anything is dialled, and must be {@code https} with a path
 * <li>its host is resolved and refused if it lands on a special-use address, which is what stops the server
 * being used to reach cloud metadata services or anything on the private network behind it
 * <li>redirects are not followed, so a public URL cannot bounce the fetch somewhere internal
 * <li>the response is size limited, so a client id pointing at an endless stream cannot exhaust memory
 * </ul>
 *
 * <p>One residual weakness is worth naming: the host is resolved for the check and then resolved again by
 * the HTTP client when it connects, so a name that changes its answer between the two could slip past. Fully
 * closing that means pinning the connection to the address that was checked. What gets through is narrow.
 * The https requirement means the connection fails at the TLS handshake, since no internal service holds a
 * certificate for the caller's host name, so no request is sent. And transport failures are reported to the
 * caller only generically, so the attempt does not tell them whether an internal address or port exists.
 */
@Slf4j
public class ClientIdMetadataResolver {

    /**
     * The specification recommends reading at most five kilobytes.
     */
    static final int MAX_DOCUMENT_BYTES = 5 * 1024;


    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final WebClient webClient;

    private final Duration cacheTtl;

    private final boolean allowLoopback;

    /** How many client documents are kept. Callers choose client identifiers, so this has to be bounded. */
    static final int MAX_CACHED_CLIENTS = 1_000;

    private final ExpiringCache<ClientIdMetadata> cache = new ExpiringCache<>(MAX_CACHED_CLIENTS);

    /**
     * @param webClientBuilder used to build a dedicated client with a small buffer and no redirect following
     * @param cacheTtl how long a successfully fetched document is reused
     * @param allowLoopback whether to permit loopback client identifiers, which the specification allows
     *     only for development and only when this server is itself on loopback
     */
    public ClientIdMetadataResolver(WebClient.Builder webClientBuilder, Duration cacheTtl,
            boolean allowLoopback) {
        this.webClient = webClientBuilder.clone()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(MAX_DOCUMENT_BYTES))
                .build();
        this.cacheTtl = cacheTtl;
        this.allowLoopback = allowLoopback;
        if (allowLoopback) {
            log.warn("Loopback client identifiers are enabled, including over plain http. This is a "
                    + "development setting: it lets a client id point at this machine, and must not be used "
                    + "in a deployment that anyone else can reach.");
        }
    }

    /**
     * Resolves a client identifier to its metadata.
     *
     * @param clientId the Client Identifier URL from the authorization request
     * @return the client's metadata
     */
    public Mono<ClientIdMetadata> resolve(String clientId) {
        String error = ClientIdUrl.validationError(clientId, this.allowLoopback);
        if (error != null) {
            return Mono.error(new ClientIdMetadataException(error));
        }
        ClientIdMetadata cached = this.cache.getFresh(clientId);
        if (cached != null) {
            return Mono.just(cached);
        }
        return assertNotSpecialUse(clientId, "client_id")
                .then(fetch(clientId, "client metadata document"))
                .map(document -> validate(clientId, document))
                .doOnNext(metadata -> this.cache.put(clientId, metadata, Instant.now().plus(this.cacheTtl)));
    }

    /**
     * Fetches a JSON document from a URL the client chose, under the same rules as its metadata document:
     * https with a path, a host that does not resolve to a special-use address, no redirect following and
     * a size limit. A {@code jwks_uri} is as attacker-controlled as a {@code client_id}, so it gets the
     * same treatment rather than a plain {@code WebClient} call.
     *
     * @param url the URL to fetch
     * @param what what is being fetched, for error messages
     * @return the response body
     */
    public Mono<String> fetchFromClientUrl(String url, String what) {
        String error = ClientIdUrl.validationError(url, this.allowLoopback);
        if (error != null) {
            return Mono.error(new ClientIdMetadataException("The " + what + " is unusable: " + error));
        }
        return assertNotSpecialUse(url, what).then(fetch(url, what));
    }

    /**
     * Removes a client from the cache, so the next authorization request re-reads its document.
     *
     * @param clientId the Client Identifier URL
     */
    public void evict(String clientId) {
        this.cache.remove(clientId);
    }

    private Mono<Void> assertNotSpecialUse(String url, String what) {
        String host = URI.create(url).getHost();
        return Mono.fromCallable(() -> InetAddress.getAllByName(host))
                // Name resolution blocks, and this runs on an event loop thread.
                .subscribeOn(Schedulers.boundedElastic())
                .onErrorMap(UnknownHostException.class, failure -> new ClientIdMetadataException(
                        "The " + what + " host '" + host + "' does not resolve."))
                .flatMap(addresses -> {
                    for (InetAddress address : addresses) {
                        if (this.allowLoopback && address.isLoopbackAddress()) {
                            continue;
                        }
                        if (SpecialUseAddresses.isSpecialUse(address)) {
                            log.warn("Refused a {} whose host {} resolves to the special-use "
                                    + "address {}.", what, host, address.getHostAddress());
                            return Mono.error(new ClientIdMetadataException(
                                    "The " + what + " host resolves to an address this server will not "
                                            + "fetch from."));
                        }
                    }
                    return Mono.empty();
                });
    }

    private Mono<String> fetch(String url, String what) {
        return this.webClient.get()
                .uri(URI.create(url))
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                // A redirect is not followed, per the specification: a public URL that bounces the fetch
                // somewhere internal would defeat the address check above.
                .onStatus(status -> status.is3xxRedirection(), response -> Mono.error(
                        new ClientIdMetadataException(
                                "The URL for the " + what + " redirected, which is not followed.")))
                .onStatus(status -> !status.is2xxSuccessful(), response -> Mono.error(
                        new ClientIdMetadataException("The URL for the " + what + " answered "
                                + response.statusCode().value() + "; it must be served with 200 OK.")))
                .bodyToMono(String.class)
                // The limit is reported from inside the body decoder, so WebClient hands it back wrapped;
                // matching only the top-level type would let this surface as an unexplained transport error.
                .onErrorMap(ClientIdMetadataResolver::isTooLarge, failure -> new ClientIdMetadataException(
                        "The " + what + " is larger than the " + MAX_DOCUMENT_BYTES
                                + " bytes this server will read."))
                // Transport failures are logged in full but reported generically. Their messages name the
                // address that was dialled and why it failed (refused, timed out, certificate rejected), which
                // would let a caller map which internal addresses and ports exist.
                .onErrorMap(failure -> !(failure instanceof ClientIdMetadataException), failure -> {
                    log.warn("Could not fetch the {} at {}: {}", what, url, failure.toString());
                    return new ClientIdMetadataException("Could not fetch the " + what + ".", failure);
                });
    }

    private static boolean isTooLarge(Throwable failure) {
        for (Throwable candidate = failure; candidate != null; candidate = candidate.getCause()) {
            if (candidate instanceof DataBufferLimitException) {
                return true;
            }
            if (candidate.getCause() == candidate) {
                break;
            }
        }
        return false;
    }

    private ClientIdMetadata validate(String clientId, String body) {
        Map<String, Object> raw;
        ClientIdMetadata metadata;
        try {
            raw = JSON.readValue(body, JSON.getTypeFactory()
                    .constructMapType(java.util.LinkedHashMap.class, String.class, Object.class));
            metadata = JSON.readValue(body, ClientIdMetadata.class);
        }
        catch (RuntimeException failure) {
            throw new ClientIdMetadataException(
                    "The client metadata document is not valid JSON for a client document.", failure);
        }
        // A property, not a substring of the body: 'client_secret_basic' is a perfectly legitimate value of
        // token_endpoint_auth_method, and rejecting a document for containing those characters would refuse
        // clients that are merely declaring how they would authenticate.
        for (String forbidden : List.of("client_secret", "client_secret_expires_at")) {
            if (raw.containsKey(forbidden)) {
                // The document is world readable, so anything secret in it is already public. Refusing is
                // kinder than quietly treating a published secret as a credential.
                throw new ClientIdMetadataException("The client metadata document declares '" + forbidden
                        + "'. A document served at a public URL must not carry a secret.");
            }
        }
        // Simple string comparison, as specified. Without this a document could claim any identity it
        // liked, and the URL would stop being the client's name.
        if (!clientId.equals(metadata.clientId())) {
            throw new ClientIdMetadataException("The client metadata document declares client_id '"
                    + metadata.clientId() + "', which does not match the URL it was fetched from.");
        }
        if (metadata.redirectUris().isEmpty()) {
            throw new ClientIdMetadataException(
                    "The client metadata document declares no redirect_uris.");
        }
        if (metadata.usesPrivateKeyJwt() && (metadata.jwksUri() == null || metadata.jwksUri().isBlank())) {
            throw new ClientIdMetadataException("The client metadata document declares "
                    + "token_endpoint_auth_method 'private_key_jwt' but no jwks_uri, so there is no key "
                    + "to verify its assertion against.");
        }
        return metadata;
    }
}
