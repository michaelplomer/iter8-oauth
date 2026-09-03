# CI wiring, mirroring oura-mcp / whatable. The GitHub connection is made by hand — it needs the
# Cloud Build GitHub App installed on the repository and authorised by a person — and its id comes in
# as a variable. Empty github_connection_id skips the trigger, so the deploy can be applied and the
# first image pushed manually before CI is wired.

resource "google_cloudbuildv2_repository" "repo" {
  count = var.github_connection_id == "" ? 0 : 1

  name              = var.github_repository
  location          = var.region
  parent_connection = var.github_connection_id
  remote_uri        = "https://github.com/${var.github_owner}/${var.github_repository}.git"
}

resource "google_cloudbuild_trigger" "deploy_on_push" {
  count = var.github_connection_id == "" ? 0 : 1

  name        = "${var.service_name}-deploy"
  location    = var.region
  description = "Build and deploy the mcp-oauth authorization server"

  # Runs as its own identity rather than the legacy shared Cloud Build account, which is what lets the
  # permissions in service_accounts.tf be scoped to single resources.
  service_account = google_service_account.build.id

  repository_event_config {
    repository = google_cloudbuildv2_repository.repo[0].id
    push {
      branch = var.build_branch
    }
  }

  filename = "cloudbuild.yaml"

  # Kept in step with the substitutions cloudbuild.yaml declares, so the file's own defaults are only
  # used when a build is started by hand.
  substitutions = {
    _REGION  = var.region
    _REPO    = var.repository_id
    _SERVICE = google_cloud_run_v2_service.server.name
  }

  depends_on = [
    google_artifact_registry_repository_iam_member.build_may_push,
    google_cloud_run_v2_service_iam_member.build_may_deploy,
    google_service_account_iam_member.build_may_use_runtime,
    google_project_iam_member.build_may_log,
  ]
}
