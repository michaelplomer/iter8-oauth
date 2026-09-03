terraform {
  required_version = ">= 1.6"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  # State records the whole deployment. Put it somewhere durable and access-controlled before this is
  # more than one person's project.
  #
  # backend "gcs" {
  #   bucket = "plomer-platform-tfstate"
  #   prefix = "as-app/state"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region

  # Some APIs refuse a request that names no quota project; attribute them to this project.
  billing_project       = var.project_id
  user_project_override = true
}
