package de.iter8.oauth.app;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code resources} map is keyed by URL, and URLs contain dots — which Spring's relaxed binding treats as
 * nested keys unless the key is wrapped in {@code [ ]}. Getting this wrong binds an empty map, which silently
 * routes every authorization request to the default provider (so e.g. an {@code oura.read} request against the
 * oura resource is rejected as an unsupported scope). This pins the working form.
 */
class ResourceMapBindingTest {

    @Test
    void url_keyed_resource_map_binds() {
        MapConfigurationPropertySource source = new MapConfigurationPropertySource(Map.of(
                "iter8.oauth.resources[https://oura.mcp.plomer.info/mcp]", "oura",
                "iter8.oauth.resources[https://whatable.mcp.plomer.info/mcp]", "google-oidc",
                "iter8.oauth.default-provider", "google-oidc"));

        AuthorizationServerProperties props = new Binder(source)
                .bind("iter8.oauth", AuthorizationServerProperties.class)
                .get();

        assertThat(props.resources())
                .containsEntry("https://oura.mcp.plomer.info/mcp", "oura")
                .containsEntry("https://whatable.mcp.plomer.info/mcp", "google-oidc");
        assertThat(props.defaultProvider()).isEqualTo("google-oidc");
    }
}
