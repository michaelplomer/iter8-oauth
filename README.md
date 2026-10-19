# iter8-oauth

A standalone MCP **authorization server** with pluggable upstream providers, plus the libraries an MCP
resource server uses to validate its tokens. Extracted and generalized from oura-mcp's embedded AS.

Gradle 9.6 · Java 25 · Spring Boot 4.1 · Spring WebFlux.

## Why it exists

MCP clients authenticate with an OAuth 2.1 flow they discover automatically, and expect to onboard without
manual registration (via CIMD or DCR). Upstream identity providers can't offer that: Google has no dynamic
registration, and a broker like Oura exposes no public-client token flow. This server sits between them — it
onboards MCP clients (Client ID Metadata Documents + `private_key_jwt`), runs the upstream flow once against
its own registered app, and issues its own audience-bound tokens.

## Modules

| Module | Kind | What it is |
|---|---|---|
| `cimd` | library | Client ID Metadata Documents: fetch + validate a client's self-description, verify `private_key_jwt`. Provider-neutral. |
| `token` | library | The token formats shared by the authorization server and resource servers: the JWS, JWE and refresh-token codecs, the token model, and the signing and sealing keys. No Spring dependency. |
| `oauth-core` | library | The AS engine: PKCE, code/pending stores, and the `UpstreamProvider` SPI — with `BrokeredTokenProvider` and `OidcIdentityProvider`. |
| `resource-server` | library | What an MCP server consumes, depending only on `token`: protected-resource metadata, the bearer challenge, and a security chain validating AS tokens (JWS via JWKS, or JWE via the self-issued introspector). |
| `as-app` | **bootJar** | The deployable authorization server, wired from declarative config. |

`cimd`, `token`, `oauth-core`, and `resource-server` publish as artifacts (`de.iter8:*`); `as-app` deploys.

## The two token models

A provider declares its `TokenModel`, which picks the codec — **fail-closed**, so a secret-carrying provider
can never emit a readable token:

- **`SEALED_CREDENTIAL` (JWE)** — a brokering provider (Oura) seals the upstream credential inside an
  *encrypted* token; the resource server decrypts it with a private key it alone holds.
- **`SIGNED_IDENTITY` (JWS)** — an identity provider (Google) carries only the verified user identity in a
  *signed* token; resource servers verify it against the AS JWKS with a standard JWT decoder.

## Adding a provider is configuration

```yaml
iter8:
  oauth:
    issuer: https://oauth.plomer.info
    keys: { jws-private-key: ..., jws-public-key: ... }   # generated per-run if absent (dev)
    providers:
      google-oidc:
        type: oidc-identity
        client-id: ...            # a single OAuth client you register with Google, once
        client-secret: ...
        authorization-uri: https://accounts.google.com/o/oauth2/v2/auth
        token-uri: https://oauth2.googleapis.com/token
        jwks-uri: https://www.googleapis.com/oauth2/v3/certs
        accepted-issuers: [https://accounts.google.com, accounts.google.com]
        requested-scope: openid email
        allowed-hosted-domains: [plomer.info]   # whole Workspace, by the hd claim (not email suffix)
        allowed-emails: [friend@gmail.com]      # individual external accounts
        scopes-supported: [whatable.read, whatable.write]
    resources:
      # URL keys contain dots, so they must be bracket-quoted or Spring binds the map empty.
      "[https://whatable.mcp.plomer.info/mcp]": google-oidc
    default-provider: google-oidc
```

## A resource server consumes it

```yaml
iter8:
  resource-server:
    enabled: true
    resource: https://whatable.mcp.plomer.info/mcp
    authorization-servers: [https://oauth.plomer.info]
    token-validation: jws            # or jwe (then set encryption-keys)
    required-scopes: [whatable.read]
```

## Build & test

```bash
./gradlew build
```
In `oauth-core`, the tests cover token-codec round-trips and fail-closed codec selection, resource encryption
keys, and the Google domain and allowlist gate. In `as-app`, they cover resource map binding, the brokered
authorization flow, and a full context boot serving metadata, JWKS and authorize.

## Generating keys

A production deployment needs three persistent keys, supplied through the environment variables that
`application-prod.yml` reads. Without them, keys are generated per run, and every restart invalidates
outstanding tokens. Store the output in your secret manager rather than in files.

`ITER8_OAUTH_REFRESH_TOKEN_KEY`, the key that seals refresh tokens:

```bash
openssl rand -base64 32 | tr -d '\n'
```

`ITER8_OAUTH_JWS_PRIVATE_KEY` and `ITER8_OAUTH_JWS_PUBLIC_KEY`, the key pair that signs identity tokens:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jws.pem
openssl pkey -in jws.pem -outform DER | base64 | tr -d '\n'           # private key
openssl pkey -in jws.pem -pubout -outform DER | base64 | tr -d '\n'   # public key
rm jws.pem
```
