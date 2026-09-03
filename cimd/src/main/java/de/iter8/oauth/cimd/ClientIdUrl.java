package de.iter8.oauth.cimd;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Validation of a Client Identifier URL, per section 2 of the Client ID Metadata Document specification.
 *
 * <p>These rules are not stylistic. The identifier is compared by simple string comparison everywhere it is
 * used, so anything that lets two different strings denote the same document — a dot segment, a default
 * port written explicitly, a fragment the server would drop when fetching — turns one client's identity into
 * several, or several clients' identities into one.
 */
public final class ClientIdUrl {

    private ClientIdUrl() {
    }

    /**
     * Validates a client identifier.
     *
     * @param clientId the value from the authorization request
     * @return the reason it is not a usable Client Identifier URL, or {@code null} when it is
     */
    public static String validationError(String clientId) {
        return validationError(clientId, false);
    }

    /**
     * Validates a client identifier, optionally allowing a plain HTTP loopback URL.
     *
     * <p>The loopback allowance belongs to the same development exception the specification makes for
     * fetching loopback addresses, and it extends to the scheme for the same reason it is safe to: https is
     * required so that the document cannot be altered in transit, and there is no transit to speak of
     * between a process and itself. It must not be enabled anywhere another machine can reach.
     *
     * @param clientId the value from the authorization request
     * @param allowInsecureLoopback whether {@code http} is acceptable for a loopback host
     * @return the reason it is not a usable Client Identifier URL, or {@code null} when it is
     */
    public static String validationError(String clientId, boolean allowInsecureLoopback) {
        if (clientId == null || clientId.isBlank()) {
            return "client_id is missing";
        }
        URI uri;
        try {
            uri = new URI(clientId);
        }
        catch (URISyntaxException failure) {
            return "client_id is not a valid URI";
        }
        boolean loopbackHttp = allowInsecureLoopback && "http".equals(uri.getScheme())
                && isLoopbackHost(uri.getHost());
        if (!uri.isAbsolute() || !("https".equals(uri.getScheme()) || loopbackHttp)) {
            return "client_id must be an https URL";
        }
        if (uri.getRawUserInfo() != null) {
            return "client_id must not contain a userinfo component";
        }
        if (uri.getRawFragment() != null) {
            return "client_id must not contain a fragment";
        }
        String path = uri.getRawPath();
        if (path == null || path.isEmpty() || "/".equals(path)) {
            return "client_id must contain a path component";
        }
        for (String segment : path.split("/", -1)) {
            if (".".equals(segment) || "..".equals(segment)) {
                return "client_id must not contain dot-segments";
            }
        }
        if (uri.getHost() == null) {
            return "client_id must contain a host";
        }
        return null;
    }

    /**
     * @param clientId the value from the authorization request
     * @return whether it is a usable Client Identifier URL
     */
    public static boolean isValid(String clientId) {
        return validationError(clientId) == null;
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "[::1]".equals(host)
                || "::1".equals(host);
    }
}
