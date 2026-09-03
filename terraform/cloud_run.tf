resource "google_cloud_run_v2_service" "server" {
  name     = var.service_name
  location = var.region

  # Public ingress; whether an unauthenticated caller may actually invoke is the allUsers binding
  # below, gated on allow_unauthenticated (true by default for the AS — see the variable).
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = false

  template {
    service_account = google_service_account.runtime.email
    timeout         = "${var.request_timeout_seconds}s"

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }

    containers {
      image = var.placeholder_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        startup_cpu_boost = true
        cpu_idle          = true
      }

      dynamic "env" {
        for_each = local.environment
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = local.secrets
        content {
          name = env.value
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.as[env.key].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  # Cloud Build owns which image is deployed; Terraform owns the shape of the service. Without this,
  # every apply after a deploy would roll the service back to the placeholder.
  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_secret_manager_secret_iam_member.runtime_may_read,
    google_secret_manager_secret_version.placeholder,
  ]
}

locals {
  environment = {
    # Activate the production profile (application-prod.yml).
    SPRING_PROFILES_ACTIVE = "prod"

    # This server's public issuer. Blank when no custom domain is mapped: the AS then derives it per
    # request, which is safe behind Cloud Run's proxy (forward-headers-strategy=framework).
    ITER8_OAUTH_ISSUER = var.custom_domain == "" ? "" : "https://${var.custom_domain}"

    # Non-secret provider client ids (the secrets come from Secret Manager, above).
    GOOGLE_OIDC_CLIENT_ID = var.google_oidc_client_id
    OURA_CLIENT_ID        = var.oura_client_id
  }
}

# An authorization server must be publicly callable. Unlike whatable this defaults on: discovery and
# the OAuth endpoints are reached by unauthenticated clients. (An org domain-restriction policy would
# block this; the org repo deliberately sets none.)
resource "google_cloud_run_v2_service_iam_member" "public" {
  count = var.allow_unauthenticated ? 1 : 0

  location = google_cloud_run_v2_service.server.location
  name     = google_cloud_run_v2_service.server.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
