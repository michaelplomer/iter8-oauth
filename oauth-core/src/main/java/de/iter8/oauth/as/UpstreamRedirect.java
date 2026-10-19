package de.iter8.oauth.as;

import java.net.URI;

/**
 * Starts the upstream leg of an authorization: stores the request under a fresh state value and builds the
 * URL that sends the user to the upstream provider. Used both by the authorization endpoint, for trusted
 * clients, and by the consent endpoint, once the user has allowed a client.
 */
final class UpstreamRedirect {

    private UpstreamRedirect() {
    }

    /**
     * @param pendingAuthorizations where the request waits for the callback
     * @param uris this server's URLs
     * @param provider the upstream provider for the request
     * @param authorization the request, with the expiry it should have from now
     * @return the upstream provider's authorization URL
     * @throws StoreFullException when too many requests are waiting for the callback
     */
    static URI start(PendingAuthorizationStore pendingAuthorizations, AuthorizationServerUris uris,
            UpstreamProvider provider, PendingAuthorization authorization) {
        String upstreamState = pendingAuthorizations.store(authorization);
        String callbackUri = uris.absolute(AsPaths.CALLBACK_PATH);
        return provider.authorizationRequestUri(upstreamState, callbackUri, authorization.scope());
    }
}
