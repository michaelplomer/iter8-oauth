package de.iter8.oauth.as;

import java.net.URI;
import java.util.List;

import reactor.core.publisher.Mono;

import de.iter8.oauth.token.IssuedTokenCodec;
import de.iter8.oauth.token.TokenModel;

/**
 * An upstream identity or authorization provider this server brokers for.
 *
 * <p>This is the one seam that differs between deployments. Everything else in the engine — PKCE, the
 * code/pending stores, client onboarding via CIMD, the metadata and the endpoints — is provider-neutral.
 * A brokering provider (Oura) completes an upstream OAuth exchange and returns a credential to seal; an
 * identity provider (Google OIDC) verifies an ID token, applies its authorization gate, and returns the
 * verified identity. The {@link #tokenModel()} it declares decides which {@link IssuedTokenCodec} is used,
 * and that decision is anchored here rather than inferred from configuration.
 */
public interface UpstreamProvider {

    /**
     * @return the stable id used to route callbacks and refreshes back to this provider (e.g. "oura")
     */
    String id();

    /**
     * @return how tokens standing for this provider's results are carried; see {@link TokenModel}
     */
    TokenModel tokenModel();

    /**
     * @return the scopes this authorization server advertises and accepts for this provider
     */
    List<String> scopesSupported();

    /**
     * Builds the URL to send the user to, to authorize upstream.
     *
     * @param state this server's own single-use state for the upstream leg
     * @param callbackUri this server's absolute callback URL, which the upstream re-checks
     * @param requestedScope the scope the client asked for, or {@code null}
     * @return the absolute upstream authorization URL
     */
    URI authorizationRequestUri(String state, String callbackUri, String requestedScope);

    /**
     * Completes the upstream round trip: exchanges the code, verifies the result, and applies any
     * authorization gate.
     *
     * @param code the authorization code the upstream returned
     * @param callbackUri the redirect URL the code was issued against (re-checked upstream)
     * @param pending the validated request this callback completes
     * @return the upstream result to seal into this server's tokens
     */
    Mono<UpstreamResult> completeCallback(String code, String callbackUri, PendingAuthorization pending);

    /**
     * Produces a fresh result from a prior one, at refresh time.
     *
     * <p>A broker calls upstream with the sealed refresh credential in {@code previous}. An identity
     * provider can re-issue from the identity in {@code previous} without a round trip, within the refresh
     * token's own lifetime. Either may error to force the user to authorize again.
     *
     * @param previous the material rebuilt from the presented refresh token
     * @return a fresh result
     */
    Mono<UpstreamResult> refresh(UpstreamResult previous);
}
