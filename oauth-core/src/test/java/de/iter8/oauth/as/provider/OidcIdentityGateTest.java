package de.iter8.oauth.as.provider;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import de.iter8.oauth.as.UpstreamAuthorizationException;
import de.iter8.oauth.as.UpstreamResult;

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
                List.of("example.com"),         // allowed hosted domain
                List.of("bob@example.org"),     // allowlisted external account
                List.of("notes.read"));
        return new OidcIdentityProvider("google-oidc", config, WebClient.builder());
    }

    @Test
    void admits_a_workspace_account_by_hosted_domain() {
        assertThat(provider().admits("alice@example.com", "example.com")).isTrue();
    }

    @Test
    void refuses_a_matching_email_suffix_without_the_hosted_domain_claim() {
        // An example.com email with no hd claim is not a verified Workspace account, so it is refused —
        // this is why the gate uses hd rather than the email suffix.
        assertThat(provider().admits("alice@example.com", null)).isFalse();
    }

    @Test
    void admits_an_allowlisted_external_account_case_insensitively() {
        assertThat(provider().admits("bob@example.org", null)).isTrue();
        assertThat(provider().admits("BOB@EXAMPLE.ORG", null)).isTrue();
    }

    @Test
    void refuses_a_stranger_and_a_disallowed_domain() {
        assertThat(provider().admits("carol@example.org", null)).isFalse();
        assertThat(provider().admits("mallory@example.net", "example.net")).isFalse();
    }

    @Test
    void refresh_reapplies_the_allowlist() {
        // carol@example.org is not on the allowlist, as if she had been removed after signing in.
        UpstreamResult removed = UpstreamResult.identity("carol@example.org", "notes.read",
                Map.of("email", "carol@example.org"));
        StepVerifier.create(provider().refresh(removed))
                .expectError(UpstreamAuthorizationException.class)
                .verify();

        UpstreamResult admitted = UpstreamResult.identity("alice@example.com", "notes.read",
                Map.of("email", "alice@example.com", "hd", "example.com"));
        StepVerifier.create(provider().refresh(admitted))
                .expectNextMatches(result -> result.subject().equals("alice@example.com"))
                .verifyComplete();
    }
}
