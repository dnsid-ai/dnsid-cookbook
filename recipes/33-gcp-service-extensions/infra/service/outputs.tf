output "endpoint" {
  value = "https://${var.address}"
}

output "address" {
  value = var.address
}

# The certificate the endpoint serves, public. A client trusts it and pins its fingerprint.
output "certificate_pem" {
  value = tls_self_signed_cert.edge.cert_pem
}

output "certificate_not_after" {
  value = tls_self_signed_cert.edge.validity_end_time
}

output "forwarding_rule" {
  value = google_compute_global_forwarding_rule.https.self_link
}

output "target_https_proxy" {
  value = google_compute_target_https_proxy.edge.self_link
}

output "url_map" {
  value = google_compute_url_map.edge.self_link
}

output "ssl_certificate" {
  value = google_compute_ssl_certificate.edge.self_link
}

output "origin_backend_service" {
  value = google_compute_backend_service.origin.self_link
}

output "callout_backend_service" {
  value = google_compute_backend_service.verifier.self_link
}

output "origin_neg" {
  value = google_compute_region_network_endpoint_group.origin.self_link
}

output "verifier_neg" {
  value = google_compute_region_network_endpoint_group.verifier.self_link
}

output "authz_extension" {
  value = google_network_services_authz_extension.dnsid.id
}

output "authz_policy" {
  value = google_network_security_authz_policy.dnsid.id
}

output "verifier_service" {
  value = google_cloud_run_v2_service.verifier.name
}

output "origin_service" {
  value = google_cloud_run_v2_service.origin.name
}

# The default run.app URLs, disabled. The live tests try them (deny-bypass-run-app, deny-bypass-verifier).
output "verifier_uri" {
  value = google_cloud_run_v2_service.verifier.uri
}

output "origin_uri" {
  value = google_cloud_run_v2_service.origin.uri
}

output "verifier_urls" {
  value = google_cloud_run_v2_service.verifier.urls
}

output "origin_urls" {
  value = google_cloud_run_v2_service.origin.urls
}

output "verifier_service_account" {
  value = google_service_account.verifier.email
}

output "origin_service_account" {
  value = google_service_account.origin.email
}

output "verifier_scaling" {
  value = {
    min = 1
    max = var.verifier_max_instances
  }
}
