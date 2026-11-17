terraform {
  # The versions this was written and validated with (README.md, Prerequisites). The exact provider builds are
  # pinned by .terraform.lock.hcl; scripts/deploy.sh initializes with -lockfile=readonly.
  required_version = ">= 1.17.2, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.11"
    }
  }

  # State stays outside the repository: scripts/deploy.sh initializes with
  # -backend-config=path=$STATE_DIR/bootstrap/terraform.tfstate.
  backend "local" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
  # Requests are billed to and checked against the deployment's own project, so Application Default Credentials from
  # `gcloud auth application-default login` work without a separately configured quota project.
  user_project_override = true
  billing_project       = var.project_id
}
