# Offline tests of the service stage: mock providers, no credentials, nothing created. Run by scripts/test-local.sh
# (terraform test). They check this configuration's own values. What Google does with them (request fidelity, the
# end-of-stream indication, the timeout, the 500 when the verifier can't answer) is for the live tests.

mock_provider "google" {}
mock_provider "tls" {}
mock_provider "random" {}

variables {
  project_id         = "sandbox-project-1"
  region             = "us-central1"
  deployment_name    = "dnsid-gse-0a1b2c3d"
  trusted_governance = "dnsid-sandbox.io"
  address_name       = "dnsid-gse-0a1b2c3d-ip"
  address            = "203.0.113.10"
  verifier_image     = "us-central1-docker.pkg.dev/sandbox-project-1/dnsid-gse-0a1b2c3d/verifier@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  origin_image       = "us-central1-docker.pkg.dev/sandbox-project-1/dnsid-gse-0a1b2c3d/origin@sha256:2222222222222222222222222222222222222222222222222222222222222222"
}

run "the_authorization_extension_and_policy" {
  command = apply

  assert {
    condition     = google_network_services_authz_extension.dnsid.fail_open == false
    error_message = "the extension must not fail open"
  }

  assert {
    condition     = google_network_services_authz_extension.dnsid.timeout == "3s"
    error_message = "the extension's timeout must be 3,000 ms"
  }

  assert {
    condition     = google_network_services_authz_extension.dnsid.load_balancing_scheme == "EXTERNAL_MANAGED" && google_network_services_authz_extension.dnsid.location == "global"
    error_message = "the extension must be a global EXTERNAL_MANAGED extension"
  }

  assert {
    condition     = google_network_services_authz_extension.dnsid.service == google_compute_backend_service.verifier.self_link
    error_message = "the extension must call the verifier's callout backend service"
  }

  assert {
    condition     = google_network_services_authz_extension.dnsid.forward_headers == null && google_network_services_authz_extension.dnsid.forward_attributes == null
    error_message = "every request header must be forwarded (forward_headers unset), and no attributes"
  }

  assert {
    condition     = google_network_security_authz_policy.dnsid.action == "CUSTOM" && google_network_security_authz_policy.dnsid.location == "global"
    error_message = "the policy must be a global CUSTOM policy"
  }

  assert {
    condition     = google_network_security_authz_policy.dnsid.target[0].resources == tolist([google_compute_global_forwarding_rule.https.self_link]) && google_network_security_authz_policy.dnsid.target[0].load_balancing_scheme == "EXTERNAL_MANAGED"
    error_message = "the policy must target exactly the deployment's forwarding rule"
  }

  assert {
    condition     = google_network_security_authz_policy.dnsid.custom_provider[0].authz_extension[0].resources == tolist([google_network_services_authz_extension.dnsid.id])
    error_message = "the policy must name the DNSid extension"
  }

  assert {
    condition     = length(google_network_security_authz_policy.dnsid.http_rules) == 0
    error_message = "the policy must apply to every request on the rule (no http_rules)"
  }
}

run "the_load_balancer" {
  command = apply

  assert {
    condition     = google_compute_global_forwarding_rule.https.port_range == "443" && google_compute_global_forwarding_rule.https.load_balancing_scheme == "EXTERNAL_MANAGED"
    error_message = "the only forwarding rule must be HTTPS on 443, EXTERNAL_MANAGED"
  }

  assert {
    condition     = google_compute_global_forwarding_rule.https.ip_address == "203.0.113.10" && google_compute_global_forwarding_rule.https.target == google_compute_target_https_proxy.edge.id
    error_message = "the forwarding rule must use the reserved address and the HTTPS proxy"
  }

  assert {
    condition     = google_compute_target_https_proxy.edge.ssl_certificates == tolist([google_compute_ssl_certificate.edge.id]) && google_compute_target_https_proxy.edge.url_map == google_compute_url_map.edge.id
    error_message = "the proxy must serve the deployment's certificate and URL map"
  }

  assert {
    condition = (
      google_compute_url_map.edge.default_service == google_compute_backend_service.origin.id &&
      length(google_compute_url_map.edge.default_route_action) == 0 &&
      length(google_compute_url_map.edge.default_url_redirect) == 0 &&
      length(google_compute_url_map.edge.host_rule) == 0 &&
      length(google_compute_url_map.edge.path_matcher) == 0
    )
    error_message = "the URL map must send every path to Demo Bank unchanged: no route actions, rewrites, redirects, host or path rules"
  }

  assert {
    condition     = google_compute_backend_service.origin.enable_cdn == false && google_compute_backend_service.verifier.enable_cdn == false
    error_message = "Cloud CDN must be off"
  }

  assert {
    condition     = google_compute_backend_service.verifier.protocol == "HTTP2" && google_compute_backend_service.verifier.load_balancing_scheme == "EXTERNAL_MANAGED"
    error_message = "the callout backend must be HTTP/2 and EXTERNAL_MANAGED"
  }

  assert {
    condition     = [for b in google_compute_backend_service.origin.backend : b.group] == [google_compute_region_network_endpoint_group.origin.id] && [for b in google_compute_backend_service.verifier.backend : b.group] == [google_compute_region_network_endpoint_group.verifier.id]
    error_message = "each backend service must use its own serverless NEG"
  }

  assert {
    condition     = google_compute_region_network_endpoint_group.origin.cloud_run[0].service == google_cloud_run_v2_service.origin.name && google_compute_region_network_endpoint_group.verifier.cloud_run[0].service == google_cloud_run_v2_service.verifier.name
    error_message = "each NEG must point at its own Cloud Run service"
  }

  assert {
    condition     = google_compute_region_network_endpoint_group.origin.network_endpoint_type == "SERVERLESS" && google_compute_region_network_endpoint_group.verifier.network_endpoint_type == "SERVERLESS"
    error_message = "the NEGs must be serverless"
  }
}

run "the_certificate" {
  command = apply

  assert {
    condition     = tls_self_signed_cert.edge.ip_addresses == tolist(["203.0.113.10"]) && tls_self_signed_cert.edge.dns_names == null && tls_self_signed_cert.edge.uris == null
    error_message = "the certificate must name the reserved address and nothing else"
  }

  assert {
    condition     = tls_private_key.edge.algorithm == "ECDSA" && tls_private_key.edge.ecdsa_curve == "P256"
    error_message = "the certificate key must be ECDSA P-256"
  }

  assert {
    condition     = google_compute_ssl_certificate.edge.certificate == tls_self_signed_cert.edge.cert_pem
    error_message = "the load balancer must serve the generated certificate"
  }

  assert {
    condition     = output.certificate_pem == tls_self_signed_cert.edge.cert_pem && output.endpoint == "https://203.0.113.10"
    error_message = "the outputs must carry the endpoint and its certificate"
  }
}

run "the_cloud_run_services" {
  command = apply

  assert {
    condition = alltrue([for s in [google_cloud_run_v2_service.verifier, google_cloud_run_v2_service.origin] :
      s.ingress == "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER" && s.default_uri_disabled == true && s.invoker_iam_disabled == true && s.deletion_protection == false && s.location == "us-central1"
    ])
    error_message = "both services must take only internal and load balancer traffic, have the default URL disabled, allow unauthenticated invocation, and be destroyable"
  }

  assert {
    condition     = google_cloud_run_v2_service.verifier.template[0].containers[0].ports[0].name == "h2c" && google_cloud_run_v2_service.verifier.template[0].containers[0].ports[0].container_port == 8080
    error_message = "the verifier must be served as plaintext HTTP/2 (h2c) on 8080"
  }

  assert {
    condition     = google_cloud_run_v2_service.origin.template[0].containers[0].ports[0].name == "http1"
    error_message = "Demo Bank is an HTTP/1.1 service"
  }

  assert {
    condition     = google_cloud_run_v2_service.verifier.template[0].containers[0].image == var.verifier_image && google_cloud_run_v2_service.origin.template[0].containers[0].image == var.origin_image
    error_message = "the services must run the images by digest"
  }

  assert {
    condition     = sort(nonsensitive([for e in google_cloud_run_v2_service.verifier.template[0].containers[0].env : e.name])) == tolist(["DNSID_ATTESTATION_KEY", "DNSID_TRUSTED_GOVERNANCE"])
    error_message = "the verifier's settings must be DNSID_TRUSTED_GOVERNANCE and DNSID_ATTESTATION_KEY"
  }

  assert {
    condition     = nonsensitive([for e in google_cloud_run_v2_service.verifier.template[0].containers[0].env : e.value if e.name == "DNSID_TRUSTED_GOVERNANCE"]) == ["dnsid-sandbox.io"]
    error_message = "the verifier's DNSID_TRUSTED_GOVERNANCE must be the governance list"
  }

  # The identity Demo Bank accepts is only one the verifier attested: both get the deployment's own key, and nothing
  # else does.
  assert {
    condition = (
      nonsensitive([for e in google_cloud_run_v2_service.origin.template[0].containers[0].env : e.name]) == ["DNSID_ATTESTATION_KEY"] &&
      nonsensitive([for e in google_cloud_run_v2_service.origin.template[0].containers[0].env : e.value] == [random_password.attestation_key.result]) &&
      nonsensitive([for e in google_cloud_run_v2_service.verifier.template[0].containers[0].env : e.value if e.name == "DNSID_ATTESTATION_KEY"] == [random_password.attestation_key.result])
    )
    error_message = "the verifier and Demo Bank must both get DNSID_ATTESTATION_KEY from the deployment's attestation key, and Demo Bank nothing else"
  }

  assert {
    condition     = random_password.attestation_key.length == 64 && random_password.attestation_key.special == false
    error_message = "the attestation key must be 64 characters from A-Z, a-z and 0-9 (the form both services accept)"
  }

  assert {
    condition     = google_cloud_run_v2_service.verifier.template[0].scaling[0].min_instance_count == 1 && google_cloud_run_v2_service.verifier.template[0].scaling[0].max_instance_count == 3
    error_message = "the verifier must keep one warm instance and a capped maximum"
  }

  # Cloud Run refuses less than 512 MiB when CPU is always allocated, which is what an unset cpu_idle means once a
  # resources block is present ("Total memory < 512 Mi is not supported with cpu always allocated").
  assert {
    condition = alltrue([for s in [google_cloud_run_v2_service.verifier, google_cloud_run_v2_service.origin] :
      s.template[0].containers[0].resources[0].cpu_idle == true || (
        endswith(s.template[0].containers[0].resources[0].limits["memory"], "Gi") ||
        tonumber(trimsuffix(s.template[0].containers[0].resources[0].limits["memory"], "Mi")) >= 512
      )
    ])
    error_message = "a service with CPU always allocated (cpu_idle not true) needs at least 512Mi of memory"
  }

  assert {
    condition     = google_cloud_run_v2_service.verifier.template[0].containers[0].resources[0].cpu_idle == false && google_cloud_run_v2_service.origin.template[0].containers[0].resources[0].cpu_idle == true
    error_message = "the verifier keeps CPU always allocated (explicitly); Demo Bank gets CPU only during requests"
  }

  assert {
    condition     = google_cloud_run_v2_service.verifier.template[0].service_account == google_service_account.verifier.email && google_cloud_run_v2_service.origin.template[0].service_account == google_service_account.origin.email
    error_message = "each service must run as its own runtime identity"
  }
}

run "passes_governance_through" {
  command = plan

  variables {
    trusted_governance = "dnsid-sandbox.io,example.org"
  }

  assert {
    condition     = nonsensitive([for e in google_cloud_run_v2_service.verifier.template[0].containers[0].env : e.value if e.name == "DNSID_TRUSTED_GOVERNANCE"]) == ["dnsid-sandbox.io,example.org"]
    error_message = "the governance list must reach the verifier unchanged"
  }
}

run "refuses_an_image_by_tag" {
  command = plan

  variables {
    verifier_image = "us-central1-docker.pkg.dev/sandbox-project-1/dnsid-gse-0a1b2c3d/verifier:latest"
  }

  expect_failures = [var.verifier_image]
}

run "refuses_an_origin_image_by_tag" {
  command = plan

  variables {
    origin_image = "docker.io/library/node:24"
  }

  expect_failures = [var.origin_image]
}

run "refuses_an_empty_governance_list" {
  command = plan

  variables {
    trusted_governance = " "
  }

  expect_failures = [var.trusted_governance]
}

run "refuses_a_non_ip_address" {
  command = plan

  variables {
    address = "example.com"
  }

  expect_failures = [var.address]
}
