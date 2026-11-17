# Offline tests of the bootstrap stage: mock providers, no credentials, nothing created. Run by scripts/test-local.sh
# (terraform test). They check this configuration's own values, not Google's behavior.

mock_provider "google" {
  mock_data "google_project" {
    defaults = {
      number = "123456789012"
    }
  }
}

# The region is left to its default (us-central1) here.
variables {
  project_id      = "sandbox-project-1"
  deployment_name = "dnsid-gse-0a1b2c3d"
}

run "creates_the_bootstrap_resources" {
  command = apply

  assert {
    condition = toset([for s in google_project_service.required : s.service]) == toset([
      "artifactregistry.googleapis.com", "cloudbuild.googleapis.com", "compute.googleapis.com", "iam.googleapis.com",
      "networksecurity.googleapis.com", "networkservices.googleapis.com", "run.googleapis.com", "storage.googleapis.com",
    ])
    error_message = "the enabled APIs are not exactly the ones the deployment uses"
  }

  assert {
    condition     = alltrue([for s in google_project_service.required : s.disable_on_destroy == false])
    error_message = "enabled APIs must stay enabled on destroy (the documented exception)"
  }

  assert {
    condition     = google_compute_global_address.edge.name == "dnsid-gse-0a1b2c3d-ip" && google_compute_global_address.edge.address_type == "EXTERNAL" && google_compute_global_address.edge.ip_version == "IPV4"
    error_message = "the reserved address is not a uniquely named external IPv4 address"
  }

  assert {
    condition     = google_artifact_registry_repository.images.repository_id == "dnsid-gse-0a1b2c3d" && google_artifact_registry_repository.images.format == "DOCKER" && google_artifact_registry_repository.images.location == "us-central1"
    error_message = "the repository is not the deployment's own Docker repository in the region"
  }

  assert {
    condition     = google_artifact_registry_repository.images.docker_config[0].immutable_tags == true
    error_message = "image tags must be immutable"
  }

  assert {
    condition     = google_storage_bucket.build.name == "dnsid-gse-0a1b2c3d-build" && google_storage_bucket.build.force_destroy == true
    error_message = "the build bucket must be the deployment's own and removable with its objects"
  }

  assert {
    condition     = google_storage_bucket.build.public_access_prevention == "enforced" && google_storage_bucket.build.uniform_bucket_level_access == true
    error_message = "the build bucket must not be public"
  }

  assert {
    condition     = google_storage_bucket.build.soft_delete_policy[0].retention_duration_seconds == 0 && length(google_storage_bucket.build.retention_policy) == 0
    error_message = "the build bucket must keep no soft-deleted objects and have no retention policy (Cloud Build can't write logs to one)"
  }

  assert {
    condition     = google_service_account.build.account_id == "dnsid-gse-0a1b2c3d-build"
    error_message = "the build identity is not the deployment's own"
  }

  assert {
    condition     = google_artifact_registry_repository_iam_member.build_writer.role == "roles/artifactregistry.writer" && google_artifact_registry_repository_iam_member.build_writer.repository == google_artifact_registry_repository.images.name
    error_message = "the build may write images to this deployment's repository only"
  }

  assert {
    condition = (
      google_storage_bucket_iam_member.build_objects.bucket == google_storage_bucket.build.name &&
      google_storage_bucket_iam_member.build_objects.role == "roles/storage.objectAdmin" &&
      google_storage_bucket_iam_member.build_bucket_reader.bucket == google_storage_bucket.build.name &&
      google_storage_bucket_iam_member.build_bucket_reader.role == "roles/storage.legacyBucketReader"
    )
    error_message = "the build's storage grants must be on this deployment's bucket only"
  }

  assert {
    condition     = google_storage_bucket.build.location == "us-central1" && output.region == "us-central1"
    error_message = "the region does not default to us-central1"
  }

  assert {
    condition     = output.repository_url == "us-central1-docker.pkg.dev/sandbox-project-1/dnsid-gse-0a1b2c3d"
    error_message = "the repository URL is not where images are pushed"
  }

  assert {
    condition     = output.project_number == "123456789012"
    error_message = "the project number is not passed through"
  }
}

run "refuses_a_malformed_deployment_name" {
  command = plan

  variables {
    deployment_name = "Dnsid-Shared"
  }

  expect_failures = [var.deployment_name]
}

run "refuses_a_malformed_project" {
  command = plan

  variables {
    project_id = "x"
  }

  expect_failures = [var.project_id]
}

run "uses_a_given_region" {
  command = plan

  variables {
    region = "europe-west4"
  }

  assert {
    condition     = google_artifact_registry_repository.images.location == "europe-west4" && google_storage_bucket.build.location == "europe-west4"
    error_message = "the repository and the build bucket are not in the given region"
  }
}

run "refuses_a_malformed_region" {
  command = plan

  variables {
    region = "Central US"
  }

  expect_failures = [var.region]
}
