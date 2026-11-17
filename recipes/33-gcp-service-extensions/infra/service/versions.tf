terraform {
  # The versions this was written and validated with (README.md, Prerequisites). The exact provider builds are
  # pinned by .terraform.lock.hcl; scripts/deploy.sh initializes with -lockfile=readonly.
  required_version = ">= 1.17.2, < 2.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.9"
    }
  }

  # State stays outside the repository: scripts/deploy.sh initializes with
  # -backend-config=path=$STATE_DIR/service/terraform.tfstate. It holds the certificate's private key and the
  # attestation key, so STATE_DIR is private to the person who deploys.
  backend "local" {}
}

provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}
