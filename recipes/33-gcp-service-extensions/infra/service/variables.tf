variable "project_id" {
  description = "The Google Cloud project (GOOGLE_CLOUD_PROJECT)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project ID."
  }
}

variable "region" {
  description = "Where both Cloud Run services and their serverless NEGs run (GOOGLE_CLOUD_REGION)."
  type        = string

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+$", var.region))
    error_message = "region must be a Google Cloud region name, for example us-central1."
  }
}

variable "deployment_name" {
  description = "The deployment's unique name, the same as the bootstrap stage's."
  type        = string

  validation {
    condition     = can(regex("^dnsid-gse-[0-9a-f]{8}$", var.deployment_name))
    error_message = "deployment_name must be dnsid-gse- followed by 8 lowercase hexadecimal digits."
  }
}

variable "trusted_governance" {
  description = "DNSID_TRUSTED_GOVERNANCE: comma-separated governance IDs, given to the verifier unchanged. The verifier validates it at startup and refuses to start on a malformed or empty value."
  type        = string
  default     = "dnsid-sandbox.io"

  validation {
    condition     = length(trimspace(var.trusted_governance)) > 0 && !can(regex("[^A-Za-z0-9., -]", var.trusted_governance))
    error_message = "trusted_governance must be one or more governance IDs separated by commas."
  }
}

variable "address_name" {
  description = "The reserved global address's name, from the bootstrap stage."
  type        = string
}

variable "address" {
  description = "The reserved global IPv4 address, from the bootstrap stage. The certificate is issued for it."
  type        = string

  validation {
    condition     = can(cidrhost("${var.address}/32", 0))
    error_message = "address must be an IPv4 address."
  }
}

variable "verifier_image" {
  description = "The verifier image by immutable digest: <repository>/verifier@sha256:<64 hex>."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+-docker\\.pkg\\.dev/[^@]+/verifier@sha256:[0-9a-f]{64}$", var.verifier_image))
    error_message = "verifier_image must be an Artifact Registry image reference by sha256 digest."
  }
}

variable "origin_image" {
  description = "The Demo Bank image by immutable digest: <repository>/origin@sha256:<64 hex>."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]+-docker\\.pkg\\.dev/[^@]+/origin@sha256:[0-9a-f]{64}$", var.origin_image))
    error_message = "origin_image must be an Artifact Registry image reference by sha256 digest."
  }
}

variable "verifier_max_instances" {
  description = "The verifier's instance cap, which bounds cost."
  type        = number
  default     = 3
}

variable "origin_max_instances" {
  description = "Demo Bank's instance cap, which bounds cost."
  type        = number
  default     = 3
}
