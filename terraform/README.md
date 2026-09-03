# Deploying the authorization server (as-app) to Cloud Run

Deploys the mcp-oauth authorization server as a **tenant of the platform project** (`plomer-platform`,
created by the [plomer.info-gcp-org](../../plomer.info-gcp-org) repo). It reuses the org-managed central
Artifact Registry and the project's already-enabled APIs — this config owns only the service, its two
service accounts, its secrets, the domain mapping, and the CI trigger.

Served at `https://oauth.plomer.info`. It is **public by design** (`allow_unauthenticated = true`):
an authorization server's discovery and OAuth endpoints are called by unauthenticated clients.

## One-time prerequisites (not Terraformable)

1. **Google OAuth client** — in the Google console (a project with the OAuth consent screen configured;
   set user type to *External* so allowlisted gmail accounts work), create an OAuth 2.0 **Web** client.
   Authorized redirect URI: `<issuer>/oauth2/callback` (e.g. `https://oauth.plomer.info/oauth2/callback`).
   The AS uses one shared callback for every upstream provider (`AsPaths.CALLBACK_PATH`), disambiguated by
   `state` — there is no per-provider path. Note the client id and secret.
2. **Oura OAuth application** — client id/secret with the same redirect URI: `<issuer>/oauth2/callback`.
3. **Key material** — generate once, persistent across revisions:
   - JWS signing keypair (public + private) — the SIGNED_IDENTITY signing key.
   - a 32-byte symmetric refresh-token key (base64).

   No SEALED_CREDENTIAL key is configured on the AS: each brokered resource server (e.g. oura-mcp) holds its
   own encryption key and publishes the public half, which the AS discovers from that resource's RFC 9728
   metadata (`jwks_uri`).
4. **Cloud Build GitHub connection** (only if wiring CI) — install the Cloud Build GitHub App on the
   repo in the console under Repositories, then pass its id as `github_connection_id`.

## Apply

```bash
cp terraform.tfvars.example terraform.tfvars   # then edit (client ids, connection id)
terraform init
terraform apply
```

This creates the service on the placeholder image, the SAs, the (empty) secrets, the domain mapping,
and — if `github_connection_id` is set — the build trigger.

## Then, in order

1. **Upload the secret values** (see `terraform output secret_upload_commands`):
   ```bash
   gcloud secrets versions add iter8-oauth-jws-private-key           --project=plomer-platform --data-file=jws-private.pem
   gcloud secrets versions add iter8-oauth-jws-public-key            --project=plomer-platform --data-file=jws-public.pem
   gcloud secrets versions add iter8-oauth-refresh-token-key         --project=plomer-platform --data-file=refresh.b64
   gcloud secrets versions add iter8-oauth-google-oidc-client-secret --project=plomer-platform --data-file=-
   gcloud secrets versions add iter8-oauth-oura-client-secret        --project=plomer-platform --data-file=-
   ```
2. **Add the DNS record** the mapping asks for (`terraform output custom_domain_dns_record`) at the
   plomer.info registrar, and wait for the managed certificate to go active.
3. **Ship a real image** — push to `main` (if CI is wired) or build/push and deploy by hand:
   ```bash
   gcloud builds submit --config cloudbuild.yaml --project plomer-platform \
     --substitutions=SHORT_SHA=$(git rev-parse --short HEAD)
   ```
4. **Verify** discovery once the cert is live:
   ```bash
   curl -s https://oauth.plomer.info/.well-known/oauth-authorization-server | jq .
   ```

## Notes

- The provider/resource wiring (issuer, endpoints, allowed domains, the resource→provider map) lives in
  `as-app/src/main/resources/application-prod.yml`, activated by `SPRING_PROFILES_ACTIVE=prod`. Add
  external gmail accounts under `providers.google-oidc.allowed-emails` there.
- If the build SA must also *pull* from the central registry (it already gets writer here), add its
  email to `artifact_registry_readers` in the org repo.
- State is local until the GCS backend in `versions.tf` is uncommented.
