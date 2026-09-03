package de.iter8.oauth.as;

/**
 * Raised when an upstream provider authenticated the user but will not authorize them — for example an
 * identity provider whose verified email is outside the permitted domain and not on the allowlist.
 *
 * <p>Distinct from a transport or protocol failure: the user is known, and the answer is no. The callback
 * turns it into an {@code access_denied} back to the MCP client.
 */
public class UpstreamAuthorizationException extends RuntimeException {

    public UpstreamAuthorizationException(String message) {
        super(message);
    }
}
