# The AS's secrets: its persistent token keys and the upstream client secrets. The containers live
# here; the values are added out of band (never in Terraform / never in state) — see the
# secret_upload_commands output and the README runbook.
#
# The map is keyed by secret name and valued by the environment variable the container reads it as
# (matching the ${...} placeholders in application-prod.yml).
locals {
  secrets = {
    "iter8-oauth-jws-public-key"            = "ITER8_OAUTH_JWS_PUBLIC_KEY"
    "iter8-oauth-jws-private-key"           = "ITER8_OAUTH_JWS_PRIVATE_KEY"
    "iter8-oauth-refresh-token-key"         = "ITER8_OAUTH_REFRESH_TOKEN_KEY"
    "iter8-oauth-google-oidc-client-secret" = "GOOGLE_OIDC_CLIENT_SECRET"
    "iter8-oauth-oura-client-secret"        = "OURA_CLIENT_SECRET"
  }
}

resource "google_secret_manager_secret" "as" {
  for_each = local.secrets

  secret_id = each.key

  replication {
    auto {}
  }
}

# The runtime service account may read them, and nothing else may.
resource "google_secret_manager_secret_iam_member" "runtime_may_read" {
  for_each = google_secret_manager_secret.as

  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

# Cloud Run checks every secret reference when it creates a revision and refuses one whose version
# cannot be found, so a secret with no versions fails the apply that creates the service. A harmless
# placeholder version satisfies that check; the real values are uploaded before the first application
# image is deployed (the placeholder image reads no secrets, so a meaningless value costs nothing).
resource "google_secret_manager_secret_version" "placeholder" {
  for_each = local.secrets

  secret      = google_secret_manager_secret.as[each.key].id
  secret_data = "placeholder: add a real version with gcloud secrets versions add"
}
