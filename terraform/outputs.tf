output "service_url" {
  description = "The service's own run.app URL."
  value       = google_cloud_run_v2_service.server.uri
}

output "issuer" {
  description = "The authorization server's public issuer (also its base for /.well-known/*)."
  value       = var.custom_domain == "" ? google_cloud_run_v2_service.server.uri : "https://${var.custom_domain}"
}

output "image_repository" {
  description = "Where builds push the image (the shared platform registry)."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.repository_id}"
}

output "secret_upload_commands" {
  description = "Terraform creates the secrets empty; these add the real values before the first real deploy."
  value = join("\n", [
    for name, _ in local.secrets :
    "gcloud secrets versions add ${name} --project=${var.project_id} --data-file=PATH"
  ])
}

output "runtime_service_account" {
  description = "Identity the AS runs as."
  value       = google_service_account.runtime.email
}

output "build_service_account" {
  description = "Identity builds run as (add to the org repo's artifact_registry_readers if it must also pull)."
  value       = google_service_account.build.email
}

output "public_access" {
  description = "Whether the AS endpoint is publicly callable (it must be)."
  value       = var.allow_unauthenticated ? "PUBLIC (allUsers can invoke) — required for an authorization server" : "PRIVATE — WARNING: OAuth discovery/flows will be unreachable; set allow_unauthenticated=true"
}

output "custom_domain_dns_record" {
  description = "The DNS record the mapping is waiting for, to be created at the plomer.info registrar."
  value = var.custom_domain == "" ? "none — set custom_domain to map one" : try(
    join("\n", [
      for record in google_cloud_run_domain_mapping.custom[0].status[0].resource_records :
      format("%s IN %s %s", coalesce(record.name, var.custom_domain), record.type, record.rrdata)
    ]),
    "mapping created, records not reported yet — re-run terraform refresh"
  )
}

output "ci_status" {
  description = "Whether the Cloud Build trigger was created."
  value       = var.github_connection_id == "" ? "no trigger — set github_connection_id to wire CI (build/push manually meanwhile)" : "trigger '${var.service_name}-deploy' on ${var.build_branch}"
}
