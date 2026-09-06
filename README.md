# mcp-oauth

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
| `oauth-core` | library | The AS engine: PKCE, code/pending stores, the token layer, and the `UpstreamProvider` / `IssuedTokenCodec` SPIs — with `BrokeredTokenProvider` and `OidcIdentityProvider`. |
| `resource-server` | library | What an MCP server consumes: protected-resource metadata, the bearer challenge, and a security chain validating AS tokens (JWS via JWKS, or JWE via the self-issued introspector). |
| `as-app` | **bootJar** | The deployable authorization server, wired from declarative config. |

`cimd`, `oauth-core`, and `resource-server` publish as artifacts (`de.iter8:*`); `as-app` deploys.

## The two token models

A provider declares its `TokenModel`, which picks the codec — **fail-closed**, so a secret-carrying provider
can never emit a readable token:

- **`SEALED_CREDENTIAL` (JWE)** — a brokering provider (Oura) seals the upstream credential inside an
  *encrypted* token; the resource server decrypts it with a private key it alone holds.
- **`SIGNED_IDENTITY` (JWS)** — an identity provider (Google) carries only the verified user identity in a
  *signed* token; resource servers verify it against the AS JWKS with a standard JWT decoder.

## Adding a provider is configuration

```yaml
mcp:
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
      https://whatable.mcp.plomer.info/mcp: google-oidc
    default-provider: google-oidc
```

## A resource server consumes it

```yaml
mcp:
  resource-server:
    enabled: true
    resource: https://whatable.mcp.plomer.info/mcp
    authorization-servers: [https://oauth.plomer.info]
    token-validation: jws            # or jwe (then set access-token-private-key)
    required-scopes: [whatable.read]
```

## Build & test

```bash
./gradlew build
```
13 tests: token-codec round-trips + fail-closed selection, the Google domain/allowlist gate (`oauth-core`),
and a full context boot serving metadata/JWKS/authorize (`as-app`).

## Status

Slice 1 (this repo) is complete and builds green. Next: adopt `resource-server` in whatable (identity/JWS,
using the Google email as the user id) and in oura-mcp (broker/JWE); then promote `as-app` to a deployed
service with its Terraform.

# Token generation
Refresh sealing token
```shell
openssl rand -base64 32 | tr -d '\n' | gcloud secrets versions add iter8-oauth-refresh-token-key --project=plomer-platform --data-file=-
```

```shell
set -e; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jws.pem && openssl pkey -in jws.pem -outform DER | base64 | gcloud secrets versions add iter8-oauth-jws-private-key --project=plomer-platform --data-file=- && openssl pkey -in jws.pem -pubout -outform DER | base64 | gcloud secrets versions add iter8-oauth-jws-public-key --project=plomer-platform --data-file=- && rm jws.pem
```