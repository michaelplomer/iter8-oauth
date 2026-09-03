package de.iter8.oauth.as;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * A sealing key store over one or more keyed encryption JWKs, selecting the private half by {@code kid}. This
 * is the rotation-ready form: publish the current key (and, during a rollover, the retiring one) and keep the
 * retired private half until tokens sealed to it have expired.
 */
public final class KeyedSealingKeyStore implements SealingKeyStore {

    private final Map<String, JWK> byKid = new LinkedHashMap<>();

    private final JWKSet publicSet;

    /**
     * @param keys the private encryption JWKs this server holds; the first is the current one for publishing
     */
    public KeyedSealingKeyStore(List<JWK> keys) {
        for (JWK key : keys) {
            this.byKid.put(key.getKeyID(), key);
        }
        this.publicSet = new JWKSet(keys.stream().map(JWK::toPublicJWK).toList());
    }

    @Override
    public Optional<JWK> decryptionKey(String kid) {
        if (kid == null) {
            // A token without a kid can only be meant for the sole key, if there is one.
            return (this.byKid.size() == 1) ? Optional.of(this.byKid.values().iterator().next())
                    : Optional.empty();
        }
        return Optional.ofNullable(this.byKid.get(kid));
    }

    @Override
    public JWKSet publicJwks() {
        return this.publicSet;
    }
}
