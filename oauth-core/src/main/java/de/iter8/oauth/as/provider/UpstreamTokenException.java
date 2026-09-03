package de.iter8.oauth.as.provider;

/**
 * Raised when an upstream provider will not issue or verify a token — a transport or protocol failure, as
 * opposed to a user who is authenticated but not permitted (which is an
 * {@link de.iter8.oauth.as.UpstreamAuthorizationException}).
 */
public class UpstreamTokenException extends RuntimeException {

    public UpstreamTokenException(String message) {
        super(message);
    }

    public UpstreamTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
