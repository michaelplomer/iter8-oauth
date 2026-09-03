package de.iter8.oauth.rs;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

/**
 * Activates the MCP resource-server pieces in a consumer application: the properties, the security chain
 * (open or protected, by {@code iter8.resource-server.enabled}), and the protected-resource-metadata endpoint.
 *
 * <p>A consuming MCP server gets all of this by depending on this library and setting
 * {@code iter8.resource-server.*}; nothing needs to be scanned or imported by hand.
 */
@AutoConfiguration
@EnableConfigurationProperties(McpResourceServerProperties.class)
@Import({ McpResourceServerConfiguration.class, ProtectedResourceMetadataController.class,
        ResourceEncryptionJwksController.class })
public class McpResourceServerAutoConfiguration {
}
