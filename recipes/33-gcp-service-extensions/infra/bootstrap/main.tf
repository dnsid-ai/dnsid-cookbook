# Bootstrap stage: what the images and the certificate need before the service stage can be applied. The APIs the
# deployment uses, the reserved global address the certificate is issued for, the Artifact Registry repository the
# images are published to, and the image build's own identity, storage and narrowly scoped grants.
#
# Everything here is destroyed by scripts/teardown.sh, after the service stage, except the enabled APIs: they stay
# enabled (disable_on_destroy = false). They cost nothing, may be shared with other work in the project, and disabling
# them could break it.

locals {
  name = var.deployment_name
  labels = {
    "dnsid-deployment" = var.deployment_name
    "managed-by"       = "terraform"
  }
  services = toset([
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "compute.googleapis.com",
    "iam.googleapis.com",
    "networksecurity.googleapis.com",
    "networkservices.googleapis.com",
    "run.googleapis.com",
    "storage.googleapis.com",
  ])
}

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_project_service" "required" {
  for_each = local.services

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# The load balancer's address. The self-signed certificate is issued for it, so it exists before the service stage.
resource "google_compute_global_address" "edge" {
  name         = "${local.name}-ip"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  labels       = local.labels

  depends_on = [google_project_service.required]
}

resource "google_artifact_registry_repository" "images" {
  repository_id = local.name
  location      = var.region
  format        = "DOCKER"
  description   = "DNSid verifier and Demo Bank images for deployment ${local.name}"
  labels        = local.labels

  docker_config {
    immutable_tags = true
  }

  depends_on = [google_project_service.required]
}

# The image build's source uploads and its logs, so no implicit Cloud Build bucket is created outside this deployment.
# force_destroy lets teardown remove the bucket with its objects; soft delete is off, so removed objects are gone.
resource "google_storage_bucket" "build" {
  name                        = "${local.name}-build"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = local.labels

  soft_delete_policy {
    retention_duration_seconds = 0
  }

  lifecycle_rule {
    condition {
      age = 1
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required]
}

# The build's own identity instead of the default Cloud Build service account, with only what the build needs.
resource "google_service_account" "build" {
  account_id   = "${local.name}-build"
  display_name = "DNSid image build (${local.name})"
  description  = "Builds, validates and publishes the images of DNSid deployment ${local.name}."

  depends_on = [google_project_service.required]
}

# Publish images to this deployment's repository only.
resource "google_artifact_registry_repository_iam_member" "build_writer" {
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.build.email}"
}

# Read the uploaded source and write the build logs, in this deployment's bucket only (and read the bucket's own
# metadata, which writing logs to a user-specified bucket checks).
resource "google_storage_bucket_iam_member" "build_objects" {
  bucket = google_storage_bucket.build.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.build.email}"
}

resource "google_storage_bucket_iam_member" "build_bucket_reader" {
  bucket = google_storage_bucket.build.name
  role   = "roles/storage.legacyBucketReader"
  member = "serviceAccount:${google_service_account.build.email}"
}
