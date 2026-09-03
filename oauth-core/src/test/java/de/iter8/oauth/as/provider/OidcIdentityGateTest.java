package de.iter8.oauth.as.provider;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The Google authorization gate: admit a verified account when its Workspace hosted domain is allowed, or
 * its email is on the allowlist. Crucially, admission keys off the {@code hd} claim, not the email suffix.
 */
class OidcIdentityGateTest {

    private OidcIdentityProvider provider() {
        OidcIdentityProvider.Config config = new OidcIdentityProvider.Config(
                "client-id", "client-secret",
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                "https://example.test/jwks",           // never fetched in this test
                List.of("https://accounts.google.com"),
                "openid email",
                List.of("plomer.info"),                 // allowed hosted domain
                List.of("friend@gmail.com"),            // allowlisted external account
                List.of("whatable.read"));
        return new OidcIdentityProvider("google-oidc", config, WebClient.builder());
    }

    @Test
    void admits_a_workspace_account_by_hosted_domain() {
        assertThat(provider().admits("me@plomer.info", "plomer.info")).isTrue();
    }

    @Test
    void refuses_a_matching_email_suffix_without_the_hosted_domain_claim() {
        // A plomer.info email with no hd claim is not a verified Workspace account, so it is refused —
        // this is why the gate uses hd rather than the email suffix.
        assertThat(provider().admits("me@plomer.info", null)).isFalse();
    }

    @Test
    void admits_an_allowlisted_external_account_case_insensitively() {
        assertThat(provider().admits("friend@gmail.com", null)).isTrue();
        assertThat(provider().admits("FRIEND@GMAIL.COM", null)).isTrue();
    }

    @Test
    void refuses_a_stranger_and_a_disallowed_domain() {
        assertThat(provider().admits("stranger@gmail.com", null)).isFalse();
        assertThat(provider().admits("someone@evil.com", "evil.com")).isFalse();
    }
}
