package de.iter8.oauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * The standalone MCP OAuth authorization server. Component scan from this package covers the engine's
 * endpoints (in the oauth-core jar, package {@code de.iter8.oauth.as}) and the app wiring
 * (package {@code de.iter8.oauth.app}).
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class McpOAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(McpOAuthApplication.class, args);
    }
}
