output "deployment_name" {
  value = var.deployment_name
}

output "project_id" {
  value = var.project_id
}

output "project_number" {
  value = data.google_project.this.number
}

output "region" {
  value = var.region
}

output "address_name" {
  value = google_compute_global_address.edge.name
}

output "address" {
  value = google_compute_global_address.edge.address
}

output "address_self_link" {
  value = google_compute_global_address.edge.self_link
}

output "repository_id" {
  value = google_artifact_registry_repository.images.repository_id
}

# Where images are pushed: <region>-docker.pkg.dev/<project>/<repository>.
output "repository_url" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "build_bucket" {
  value = google_storage_bucket.build.name
}

output "build_service_account" {
  value = google_service_account.build.email
}

output "build_service_account_id" {
  value = google_service_account.build.id
}

output "enabled_services" {
  value = sort(tolist(local.services))
}
