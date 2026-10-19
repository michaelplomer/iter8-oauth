package de.iter8.oauth.cimd;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.function.Consumer;

import io.netty.resolver.AddressResolver;
import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.InetNameResolver;
import io.netty.resolver.InetSocketAddressResolver;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Promise;
import lombok.extern.slf4j.Slf4j;
import reactor.core.scheduler.Schedulers;

/**
 * Resolves host names for fetches from client-supplied URLs, and refuses special-use addresses in the same
 * step.
 *
 * <p>Checking an address and connecting to it have to use the same lookup. Resolving the host once to check
 * it and letting the HTTP client resolve it again to connect leaves a gap: a host whose DNS answer changes
 * between the two lookups passes the check with a public address and is then connected to on an internal one
 * (DNS rebinding). Plugged into the HTTP client, this resolver is the only lookup, so the client connects to
 * exactly the addresses that were checked.
 */
@Slf4j
final class CheckedAddressResolverGroup extends AddressResolverGroup<InetSocketAddress> {

    /** Looks up a host's addresses. The JDK resolver in production; tests substitute their own. */
    @FunctionalInterface
    interface HostLookup {

        InetAddress[] lookup(String host) throws UnknownHostException;
    }

    private final HostLookup lookup;

    private final boolean allowLoopback;

    /**
     * @param lookup how host names are looked up
     * @param allowLoopback whether loopback addresses are permitted, for development
     */
    CheckedAddressResolverGroup(HostLookup lookup, boolean allowLoopback) {
        this.lookup = lookup;
        this.allowLoopback = allowLoopback;
    }

    /**
     * @param address a resolved address
     * @param allowLoopback whether loopback addresses are permitted
     * @return whether this server may connect to it to fetch a client-supplied URL
     */
    static boolean isAllowed(InetAddress address, boolean allowLoopback) {
        return (allowLoopback && address.isLoopbackAddress()) || !SpecialUseAddresses.isSpecialUse(address);
    }

    @Override
    protected AddressResolver<InetSocketAddress> newResolver(EventExecutor executor) {
        return new InetSocketAddressResolver(executor, new CheckedNameResolver(executor));
    }

    /**
     * Looks up a host and checks every address it resolves to. One forbidden address refuses the host, since
     * the HTTP client may connect to any of them.
     */
    List<InetAddress> resolveChecked(String host) throws UnknownHostException {
        InetAddress[] addresses = this.lookup.lookup(host);
        for (InetAddress address : addresses) {
            if (!isAllowed(address, this.allowLoopback)) {
                log.warn("Refused to connect to {}, which resolves to the special-use address {}.", host,
                        address.getHostAddress());
                throw new UnknownHostException(host + " resolves to a special-use address");
            }
        }
        return List.of(addresses);
    }

    private final class CheckedNameResolver extends InetNameResolver {

        CheckedNameResolver(EventExecutor executor) {
            super(executor);
        }

        @Override
        protected void doResolve(String host, Promise<InetAddress> promise) {
            resolve(host, addresses -> promise.trySuccess(addresses.get(0)), promise::tryFailure);
        }

        @Override
        protected void doResolveAll(String host, Promise<List<InetAddress>> promise) {
            resolve(host, promise::trySuccess, promise::tryFailure);
        }

        private void resolve(String host, Consumer<List<InetAddress>> onSuccess,
                Consumer<Throwable> onFailure) {
            // Name resolution blocks, and Netty calls this on an event loop thread.
            Schedulers.boundedElastic().schedule(() -> {
                try {
                    onSuccess.accept(resolveChecked(host));
                }
                catch (UnknownHostException | RuntimeException failure) {
                    onFailure.accept(failure);
                }
            });
        }
    }
}
