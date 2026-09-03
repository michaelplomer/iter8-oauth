package de.iter8.oauth.as;

import java.net.URI;

/**
 * RFC 9728 (OAuth 2.0 Protected Resource Metadata) locations. A resource identified by
 * {@code https://host/mcp} publishes its metadata at {@code https://host/.well-known/oauth-protected-resource/mcp}:
 * the well-known segment goes between the authority and the resource's own path.
 */
public final class Rfc9728 {

    private Rfc9728() {
    }

    /** The fixed well-known path, as RFC 9728 defines it. */
    public static final String METADATA_PATH = "/.well-known/oauth-protected-resource";

    /**
     * @param resource a canonical resource identifier (an absolute URL)
     * @return the URL of that resource's protected-resource-metadata document
     */
    public static String metadataUrl(String resource) {
        URI uri = URI.create(resource);
        String path = (uri.getPath() == null || uri.getPath().equals("/")) ? "" : uri.getPath();
        return uri.getScheme() + "://" + uri.getAuthority() + METADATA_PATH + path;
    }
}
