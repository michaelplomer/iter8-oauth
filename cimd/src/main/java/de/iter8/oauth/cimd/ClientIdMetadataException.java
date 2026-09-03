package de.iter8.oauth.cimd;

/**
 * Raised when a Client Identifier URL cannot be turned into a usable client.
 *
 * <p>The message is written to be shown to whoever is configuring the client, since a rejected client is
 * nearly always a mistake in their metadata document rather than an attack.
 */
public class ClientIdMetadataException extends RuntimeException {

    public ClientIdMetadataException(String message) {
        super(message);
    }

    public ClientIdMetadataException(String message, Throwable cause) {
        super(message, cause);
    }
}
