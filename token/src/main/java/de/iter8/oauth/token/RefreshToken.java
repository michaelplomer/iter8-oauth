package de.iter8.oauth.token;

/**
 * A refresh token as presented by a client, opened.
 *
 * <p>Besides what it stands for, every refresh token carries its own identifier and the identifier of its
 * family: the chain of tokens that began with one authorization and continued through each refresh. The
 * authorization server uses them to make each token single-use and to revoke the whole chain when one is
 * presented twice, which means it was copied.
 *
 * @param tokenId this token's unique identifier
 * @param familyId the identifier shared by every token descended from the same authorization
 * @param token what the token stands for
 */
public record RefreshToken(String tokenId, String familyId, IssuedToken token) {
}
