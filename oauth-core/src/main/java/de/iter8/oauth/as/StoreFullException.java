package de.iter8.oauth.as;

/**
 * Raised when an in-memory store of pending requests is at capacity. The request is refused rather than
 * letting the store grow without limit.
 */
public class StoreFullException extends RuntimeException {

    /**
     * @param message what was full
     */
    public StoreFullException(String message) {
        super(message);
    }
}
