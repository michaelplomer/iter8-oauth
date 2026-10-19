package de.iter8.oauth.as;

import de.iter8.oauth.token.IssuedTokenCodec;
import de.iter8.oauth.token.JwsTokenCodec;
import de.iter8.oauth.token.TokenModel;

/**
 * The access-token codecs available, selected by a provider's {@link TokenModel}. The refresh codec is
 * shared (always symmetric JWE) and held separately.
 */
public class TokenCodecs {

    private final IssuedTokenCodec jwe;

    private final JwsTokenCodec jws;

    /**
     * @param jwe the SEALED_CREDENTIAL codec, or {@code null} when no brokering provider is configured
     * @param jws the SIGNED_IDENTITY codec, or {@code null} when no identity provider is configured
     */
    public TokenCodecs(IssuedTokenCodec jwe, JwsTokenCodec jws) {
        this.jwe = jwe;
        this.jws = jws;
    }

    /**
     * @param model the provider's declared token model
     * @return the codec for it
     * @throws IllegalStateException when no codec is configured for that model — fail closed rather than
     *     silently substitute the other, which for a SEALED_CREDENTIAL provider would expose a credential
     */
    public IssuedTokenCodec forModel(TokenModel model) {
        IssuedTokenCodec codec = switch (model) {
            case SEALED_CREDENTIAL -> this.jwe;
            case SIGNED_IDENTITY -> this.jws;
        };
        if (codec == null) {
            throw new IllegalStateException("No token codec is configured for model " + model
                    + ". A provider declaring this model needs its key material configured.");
        }
        return codec;
    }

    /**
     * @return the SIGNED_IDENTITY codec, for publishing JWKS, or {@code null}
     */
    public JwsTokenCodec jws() {
        return this.jws;
    }
}
