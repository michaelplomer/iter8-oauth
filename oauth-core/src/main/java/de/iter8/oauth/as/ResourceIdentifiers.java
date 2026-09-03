package de.iter8.oauth.as;

import java.net.URI;
import java.util.Locale;

/**
 * Compares resource identifiers the way the MCP specification asks them to be compared.
 *
 * <p>Audience validation is a strict check by design: a token issued for one resource must not be spendable
 * at another. But strict is not the same as literal. The specification says the canonical form uses lowercase
 * scheme and host and no trailing slash, and in the same breath tells implementations to accept the other
 * spellings for robustness, because clients differ on all three and the differences mean nothing.
 *
 * <p>So scheme and host are compared case-insensitively and one trailing slash is ignored. Everything else —
 * port, path, and the path's case — is compared exactly, since those genuinely distinguish one resource from
 * another.
 */
public final class ResourceIdentifiers {

    private ResourceIdentifiers() {
    }

    /**
     * @param first a resource identifier
     * @param second another
     * @return whether they identify the same resource
     */
    public static boolean match(String first, String second) {
        if (first == null || second == null) {
            return first == null && second == null;
        }
        return canonical(first).equals(canonical(second));
    }

    /**
     * @param identifier a resource identifier
     * @return its canonical form, or the trimmed input when it cannot be parsed
     */
    public static String canonical(String identifier) {
        if (identifier == null) {
            return null;
        }
        String trimmed = identifier.trim();
        URI uri;
        try {
            uri = new URI(trimmed);
        }
        catch (Exception failure) {
            return trimmed;
        }
        if (uri.getScheme() == null || uri.getHost() == null) {
            return trimmed;
        }
        String path = (uri.getRawPath() == null) ? "" : uri.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        StringBuilder canonical = new StringBuilder()
                .append(uri.getScheme().toLowerCase(Locale.ROOT))
                .append("://")
                .append(uri.getHost().toLowerCase(Locale.ROOT));
        if (uri.getPort() != -1) {
            canonical.append(':').append(uri.getPort());
        }
        return canonical.append(path).toString();
    }
}
