package de.iter8.oauth.token;

/**
 * Raised when a presented token is not one this server will honour.
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }
}
