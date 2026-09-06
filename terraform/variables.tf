variable "project_id" {
  description = "The platform project the AS runs in. A tenant of plomer-platform, created by the org repo."
  type        = string
  default     = "plomer-platform"
}

variable "region" {
  description = "Region for the service and the build trigger."
  type        = string
  default     = "us-west1"
}

variable "service_name" {
  description = "Cloud Run service name, and the image name in the shared registry."
  type        = string
  default     = "as-app"
}

variable "repository_id" {
  description = <<-EOT
    The Artifact Registry repository holding the image. Defaults to the org-managed central "images"
    repo in the platform project — this deploy references it, it does not create it.
  EOT
  type        = string
  default     = "images"
}

variable "maven_repository_id" {
  description = <<-EOT
    The org-managed central Maven repository in the platform project that the shared libraries publish to.
    This deploy references it (grants the build SA writer); it does not create it.
  EOT
  type        = string
  default     = "maven"
}

variable "placeholder_image" {
  description = <<-EOT
    Image used only to create the service before any build has produced a real one. Cloud Build
    replaces it on the first deploy and Terraform then ignores the field, so this is never reapplied.
  EOT
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

# --- Runtime configuration -------------------------------------------------------------------

variable "custom_domain" {
  description = <<-EOT
    Hostname to serve the authorization server on. Empty leaves it on its run.app URL. The mapping's
    DNS record must be created at the plomer.info registrar (no Cloud DNS zone) — see the
    custom_domain_dns_record output.
  EOT
  type        = string
  default     = "oauth.plomer.info"
}

variable "allow_unauthenticated" {
  description = <<-EOT
    Whether to grant allUsers the run.invoker role. DEFAULT true, and deliberately so: an authorization
    server MUST be publicly reachable — its discovery (/.well-known/*) and authorize/token endpoints are
    called by unauthenticated clients. This is the opposite of whatable's default. (An org policy
    restricting domain sharing would block this binding; the org repo intentionally does not set one.)
  EOT
  type        = bool
  default     = true
}

variable "google_oidc_client_id" {
  description = "OAuth 2.0 client id for the google-oidc provider (non-secret half). From the Google console."
  type        = string
  default     = ""
}

variable "oura_client_id" {
  description = "Oura OAuth application client id for the oura broker provider (non-secret half)."
  type        = string
  default     = ""
}

# --- Build / CI ------------------------------------------------------------------------------

variable "github_owner" {
  description = "GitHub account or organisation owning the repository."
  type        = string
  default     = "michaelplomer"
}

variable "github_repository" {
  description = "GitHub repository name."
  type        = string
  default     = "mcp-oauth"
}

variable "github_connection_id" {
  description = <<-EOT
    Full resource id of an existing Cloud Build v2 GitHub connection, of the form
    projects/PROJECT/locations/REGION/connections/NAME. Cannot be created here: it requires installing
    the Cloud Build GitHub App on the repository and authorising it as a human. Make it once in the
    Cloud Build console under Repositories, then pass its id. Empty skips the trigger entirely.
  EOT
  type        = string
  default     = ""
}

variable "build_branch" {
  description = "Regular expression for branches whose pushes trigger a build and deploy."
  type        = string
  default     = "^main$"
}

# --- Scaling / cost --------------------------------------------------------------------------

variable "max_instances" {
  description = "Upper bound on instances. The AS is stateless; kept modest for a personal service."
  type        = number
  default     = 2
}

variable "request_timeout_seconds" {
  description = "Request timeout, bounding how long an instance stays alive and billed per request."
  type        = number
  default     = 60
}
