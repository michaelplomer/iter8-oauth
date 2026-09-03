package de.iter8.oauth.cimd;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * A client's own description of itself, fetched from its {@code client_id} URL.
 *
 * <p>Only the fields this authorization server acts on are modelled. The document may carry any metadata
 * from the OAuth Dynamic Client Registration registry, and unknown fields are ignored rather than rejected.
 *
 * @param clientId the client's identifier, which must equal the URL this document was fetched from
 * @param clientName a human readable name, shown on the consent screen
 * @param clientUri the client's home page, shown on the consent screen so a person can see who is asking
 * @param logoUri the client's logo
 * @param redirectUris the redirect URLs this client may use; an authorization request must match one exactly
 * @param grantTypes the grant types the client intends to use
 * @param responseTypes the response types the client intends to use
 * @param scope the scopes the client asks for, space delimited
 * @param tokenEndpointAuthMethod how the client authenticates at the token endpoint
 * @param tokenEndpointAuthMethodsSupported every method the client is willing to use, where it names
 *     more than one. Not a registered client metadata field, but clients publish it and it is the only
 *     thing that says a client which declares one method would also accept another
 * @param jwksUri where the client's public keys live, for {@code private_key_jwt}
 * @param tokenEndpointAuthSigningAlg the algorithm the client signs its assertion with, advisory: the
 *     assertion's own header is what is enforced, against this server's allowed set
 */
public record ClientIdMetadata(
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_name") String clientName,
        @JsonProperty("client_uri") String clientUri,
        @JsonProperty("logo_uri") String logoUri,
        @JsonProperty("redirect_uris") List<String> redirectUris,
        @JsonProperty("grant_types") List<String> grantTypes,
        @JsonProperty("response_types") List<String> responseTypes,
        @JsonProperty("scope") String scope,
        @JsonProperty("token_endpoint_auth_method") String tokenEndpointAuthMethod,
        @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("token_endpoint_auth_signing_alg") String tokenEndpointAuthSigningAlg
) {

    public ClientIdMetadata {
        redirectUris = (redirectUris == null) ? List.of() : List.copyOf(redirectUris);
        grantTypes = (grantTypes == null) ? List.of() : List.copyOf(grantTypes);
        responseTypes = (responseTypes == null) ? List.of() : List.copyOf(responseTypes);
        tokenEndpointAuthMethodsSupported = (tokenEndpointAuthMethodsSupported == null)
                ? List.of() : List.copyOf(tokenEndpointAuthMethodsSupported);
    }

    /**
     * @return the name to show a person on the consent screen, falling back to the identifier
     */
    public String displayName() {
        return (this.clientName != null && !this.clientName.isBlank()) ? this.clientName : this.clientId;
    }

    /**
     * Checks a requested redirect URL against the ones this client declared.
     *
     * <p>Exact string comparison, as the specification requires. Anything looser — prefix matching, ignoring
     * a trailing slash, allowing a subpath — is how authorization codes get delivered to the wrong place.
     *
     * @param redirectUri the redirect URL from the authorization request
     * @return whether the client declared it
     */
    public boolean allowsRedirectUri(String redirectUri) {
        return redirectUri != null && this.redirectUris.contains(redirectUri);
    }

    /**
     * The method a client declares when it holds a signing key rather than a shared secret. It proves
     * possession of that key at the token endpoint with an assertion this server verifies against the
     * public half published at {@link #jwksUri()} — so, like the client identifier itself, it is
     * discovered rather than provisioned, and nothing has to be agreed in advance.
     */
    public static final String PRIVATE_KEY_JWT = "private_key_jwt";

    /**
     * @return whether this client signs an assertion at the token endpoint
     */
    public boolean usesPrivateKeyJwt() {
        return PRIVATE_KEY_JWT.equals(this.tokenEndpointAuthMethod);
    }

    /**
     * Whether the client says it would also redeem as a public client.
     *
     * <p>A document can declare {@code private_key_jwt} and still list {@code none} among the methods it
     * supports, which is what ChatGPT's does. Read strictly, the singular field is a promise to sign; read
     * alongside the plural one it is a preference, and the client picks per authorization server. Demanding
     * the assertion regardless turns the client's own flexibility into a failed connection.
     *
     * @return whether {@code none} is among the methods this client says it supports
     */
    public boolean allowsPublicRedemption() {
        return this.tokenEndpointAuthMethodsSupported.contains("none");
    }

    /**
     * @return whether this client expects to authenticate with a shared secret, which cannot exist here:
     *     no registration takes place, so there is nothing for a secret to have been agreed during
     */
    public boolean usesClientSecret() {
        return this.tokenEndpointAuthMethod != null
                && !this.tokenEndpointAuthMethod.isBlank()
                && !"none".equals(this.tokenEndpointAuthMethod)
                && !usesPrivateKeyJwt();
    }
}
