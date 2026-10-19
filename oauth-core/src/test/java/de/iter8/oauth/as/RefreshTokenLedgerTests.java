package de.iter8.oauth.as;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;

class RefreshTokenLedgerTests {

    private final RefreshTokenLedger ledger = new RefreshTokenLedger(Duration.ofDays(30));

    private final Instant expiry = Instant.now().plus(Duration.ofDays(30));

    @Test
    void a_token_can_be_spent_once() {
        assertThat(this.ledger.spend("token-1", "family-a", this.expiry))
                .isEqualTo(RefreshTokenLedger.Outcome.FIRST_USE);
    }

    @Test
    void presenting_a_spent_token_again_revokes_its_family() {
        this.ledger.spend("token-1", "family-a", this.expiry);

        assertThat(this.ledger.spend("token-1", "family-a", this.expiry))
                .isEqualTo(RefreshTokenLedger.Outcome.REUSED);
        // The token the legitimate client received in exchange for token-1 is refused as well.
        assertThat(this.ledger.spend("token-2", "family-a", this.expiry))
                .isEqualTo(RefreshTokenLedger.Outcome.REVOKED);
    }

    @Test
    void revoking_one_family_leaves_others_alone() {
        this.ledger.spend("token-1", "family-a", this.expiry);
        this.ledger.spend("token-1", "family-a", this.expiry);

        assertThat(this.ledger.spend("token-9", "family-b", this.expiry))
                .isEqualTo(RefreshTokenLedger.Outcome.FIRST_USE);
    }
}
