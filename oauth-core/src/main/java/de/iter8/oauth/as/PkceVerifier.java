package de.iter8.oauth.as;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Checks a PKCE code verifier against the challenge that was registered with the authorization code.
 *
 * <p>This is what ties the token request back to whoever started the authorization. Without it, an
 * authorization code intercepted on its way through the browser could be redeemed by anybody.
 */
public final class PkceVerifier {

    private PkceVerifier() {
    }

    /**
     * @param codeVerifier the verifier from the token request
     * @param codeChallenge the challenge recorded at the authorization endpoint
     * @return whether the verifier produces the challenge
     */
    public static boolean matches(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeChallenge == null) {
            return false;
        }
        // Compared with a constant-time equality, so that a wrong verifier cannot be narrowed down by
        // timing how long the comparison takes.
        return MessageDigest.isEqual(challengeFor(codeVerifier).getBytes(StandardCharsets.US_ASCII),
                codeChallenge.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * @param codeVerifier a verifier
     * @return its S256 challenge: base64url of the SHA-256 digest, unpadded
     */
    static String challengeFor(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        }
        catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is required of every JVM", failure);
        }
    }
}
