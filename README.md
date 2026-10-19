# iter8-oauth

A standalone MCP **authorization server** with pluggable upstream providers, plus the libraries an MCP
resource server uses to validate its tokens. Extracted and generalized from oura-mcp's embedded AS.

Not affiliated with the [Iter8](https://iter8.tools) project, the Kubernetes release optimizer.

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

Releases are on Maven Central. An MCP server that validates tokens only needs `resource-server`:

```kotlin
implementation("de.iter8:resource-server:0.1.0")
```

Every push to `main` also publishes a snapshot of the next version, for example `0.1.0-SNAPSHOT`, to
`https://central.sonatype.com/repository/maven-snapshots/`. Snapshots are only for trying unreleased changes:
add that repository to your build to use them, and expect them to disappear after a while.

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
    issuer: https://auth.example.com   # required: this server's public URL
    keys: { jws-private-key: ..., jws-public-key: ... }   # generated per-run if absent (dev)
    trusted-clients:                   # optional: clients that skip the consent page
      - https://client.example.com/oauth/metadata.json
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
        allowed-hosted-domains: [example.com]   # whole Workspace, by the hd claim (not email suffix)
        allowed-emails: [bob@example.org]       # individual external accounts
        scopes-supported: [notes.read, notes.write]
    resources:
      # URL keys contain dots, so they must be bracket-quoted or Spring binds the map empty.
      "[https://notes.example.com/mcp]": google-oidc
    default-provider: google-oidc
```

## A resource server consumes it

```yaml
iter8:
  resource-server:
    enabled: true                    # required: true, or false for stdio and loopback only
    resource: https://notes.example.com/mcp
    authorization-servers: [https://auth.example.com]
    token-validation: jws            # or jwe (then set encryption-keys)
    required-scopes: [notes.read]
```

`enabled` has no default. An app that adds the library and leaves it unset, or misspells the prefix, fails at
startup instead of silently accepting every request.

## Security model and limits

To report a vulnerability, see [SECURITY.md](SECURITY.md).

**Consent.** Before sending a user to the upstream provider, the server shows a consent page naming the client
by its client ID URL, where the authorization result will be sent, and what is requested. Without it, any
client that publishes a metadata document could obtain a code for a user who had approved this server's app
at the upstream provider before, since that approval covers this server, not the client. The page's answer
only counts in the browser it was shown in. Clients listed in `trusted-clients` skip the page; list only
clients you recognize.

**Refresh tokens** are single-use. Each refresh returns a new token, and presenting a token a second time
revokes every token descended from the same authorization, so a copied token ends the session for both the
copy and the original. Refreshing an identity token applies the domain and email allowlist again.

**Client metadata** is only fetched over https, never from private or other special-use addresses (including
IPv6 forms that carry such an address), without following redirects, and with a 5 KB size limit. The address
is checked in the HTTP client's own name resolution, so the client connects to exactly the address that was
checked, and a host whose DNS answer changes cannot slip an internal address past the check.

**Limits** to be aware of:

- State is held in memory, so the server runs as a single instance. A restart loses authorizations in progress
  and forgets which refresh tokens were spent, so a token used before the restart can be used once more.
- The pending stores and caches are bounded. When full, new requests are refused rather than letting memory
  grow, so a flood of requests costs availability. There is no rate limiting in the server itself; put it
  behind a proxy or load balancer that limits requests per client.
- A client's `private_key_jwt` assertion is not tracked after use, so a captured assertion stays usable for the
  rest of its lifetime, at most five minutes.

## Build & test

```bash
./gradlew build
```
The tests cover the special-use address checks and the bounded cache (`cimd`); token codecs and fail-closed
codec selection, resource encryption keys, the allowlist gate including on refresh, refresh token reuse
detection, and the store limits (`oauth-core`); when the resource server starts and what it protects
(`resource-server`); and in `as-app`, resource map binding, the brokered authorization flow, the consent page,
and a full context boot serving metadata, JWKS and authorize.

## Releasing

1. Tag the commit with the version, such as `v0.1.0`, and push the tag. The release workflow builds, tests,
   signs and uploads the libraries to the Central Portal.
2. Check the upload in the Central Portal and publish it there. A release on Maven Central can never be changed
   or removed, so this step stays manual.
3. Set `version` in `gradle.properties` to the next snapshot, such as `0.2.0-SNAPSHOT`.

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
