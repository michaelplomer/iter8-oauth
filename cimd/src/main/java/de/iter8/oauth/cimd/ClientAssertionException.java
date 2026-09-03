package de.iter8.oauth.cimd;

/**
 * Raised when a {@code private_key_jwt} client assertion is missing, malformed, or does not verify.
 *
 * <p>The message is returned to the client as an {@code invalid_client} description, so it says which
 * check failed: the caller is a program that has to be able to correct itself.
 */
public class ClientAssertionException extends RuntimeException {

    /**
     * @param message what was wrong with the assertion
     */
    public ClientAssertionException(String message) {
        super(message);
    }
}
