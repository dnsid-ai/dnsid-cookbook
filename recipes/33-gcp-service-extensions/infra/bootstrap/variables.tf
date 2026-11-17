variable "project_id" {
  description = "The Google Cloud project to deploy into (GOOGLE_CLOUD_PROJECT). It must already exist with billing enabled."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID: 6 to 30 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "region" {
  description = "Where the Artifact Registry repository, the build and its storage live (GOOGLE_CLOUD_REGION)."
  type        = string
  default     = "us-central1"

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must be a Google Cloud region name, for example us-central1."
  }
}

variable "deployment_name" {
  description = "The unique name scripts/deploy.sh generated for this deployment and keeps in STATE_DIR. Every resource name starts with it."
  type        = string

  validation {
    condition     = can(regex("^dnsid-gse-[0-9a-f]{8}$", var.deployment_name))
    error_message = "deployment_name must be dnsid-gse- followed by 8 lowercase hexadecimal digits."
  }
}
