# A custom domain in front of the service, mapped by Cloud Run itself rather than a load balancer.
# The mapping is free and needs no other infrastructure; it is regional and not offered in every
# region — us-west1 does offer it.
#
# Domain ownership is accepted without Search Console verification because plomer.info is the
# organization's own domain. The DNS record the mapping asks for must still be created at the
# registrar (no Cloud DNS zone) — see the custom_domain_dns_record output.
resource "google_cloud_run_domain_mapping" "custom" {
  count = var.custom_domain == "" ? 0 : 1

  location = var.region
  name     = var.custom_domain

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.server.name
  }
}
