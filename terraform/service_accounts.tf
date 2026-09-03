# Two identities, so what runs the AS and what deploys it can be reasoned about separately. Both are
# tenants of the shared platform project; their grants are scoped to single resources where possible.

resource "google_service_account" "runtime" {
  account_id   = "${var.service_name}-run"
  display_name = "mcp-oauth AS runtime"
  description  = "Identity the Cloud Run service runs as. Reads its secrets (keys, client secrets) and nothing else."
}

resource "google_service_account" "build" {
  account_id   = "${var.service_name}-build"
  display_name = "mcp-oauth AS builds"
  description  = "Identity Cloud Build runs as. Pushes images to the central registry and deploys revisions."
}

# Push to the org-managed central registry (created by the org repo; referenced, not owned, here).
resource "google_artifact_registry_repository_iam_member" "build_may_push" {
  project    = var.project_id
  location   = var.region
  repository = var.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.build.email}"
}

resource "google_cloud_run_v2_service_iam_member" "build_may_deploy" {
  location = google_cloud_run_v2_service.server.location
  name     = google_cloud_run_v2_service.server.name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.build.email}"
}

# Deploying a revision means handing it the runtime identity, which counts as impersonation and is
# refused without this even when the deployer may otherwise update the service.
resource "google_service_account_iam_member" "build_may_use_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.build.email}"
}

# A build running as its own service account has no log sink by default, and refuses to start rather
# than run unlogged. Counterpart of CLOUD_LOGGING_ONLY in cloudbuild.yaml.
resource "google_project_iam_member" "build_may_log" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.build.email}"
}
