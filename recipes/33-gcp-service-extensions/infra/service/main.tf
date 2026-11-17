# Service stage: the verifier and Demo Bank on Cloud Run, and the global external Application Load Balancer in front of
# Demo Bank with the DNSid authorization extension bound to its only forwarding rule by a CUSTOM authorization policy.
#
#   agent ─HTTPS─▶ forwarding rule (443 only) ─▶ target HTTPS proxy (self-signed certificate) ─▶ URL map ─▶ Demo Bank
#                    │ authorization policy (CUSTOM) ─▶ authorization extension ─HTTP/2─▶ callout backend ─▶ verifier
#
# What keeps every other route to Demo Bank closed (README.md, Security model and known limitations): no port-80
# forwarding rule, no Cloud CDN, no URL rewrites, Cloud Run ingress limited to internal and Cloud Load Balancing traffic,
# and the default run.app URLs disabled.

locals {
  name = var.deployment_name
  labels = {
    "dnsid-deployment" = var.deployment_name
    "managed-by"       = "terraform"
  }
}

# ---------- runtime identities (no roles: the verifier fetches public DNSid data, Demo Bank calls nothing) ----------

resource "google_service_account" "verifier" {
  account_id   = "${local.name}-verifier"
  display_name = "DNSid verifier runtime (${local.name})"
}

resource "google_service_account" "origin" {
  account_id   = "${local.name}-origin"
  display_name = "Demo Bank runtime (${local.name})"
}

# ---------- the attestation key ----------

# The verifier attests every identity it sets on a request (x-dnsid-attestation, an HMAC under this key) and Demo Bank
# accepts an identity only with that attestation, so identity headers a caller sends can never pass as the verifier's,
# even while Google's load balancer forwards some requests without evaluating the authorization policy (seen for some
# minutes after the policy is created; docs/live-tests.md). One key per deployment, made here, given to these two
# services only, never an output; it stays in the private Terraform state and goes with the teardown. 64 characters
# from A-Z, a-z and 0-9 (about 380 bits).
resource "random_password" "attestation_key" {
  length  = 64
  special = false
}

# ---------- Cloud Run ----------

# The ext_proc callout. Cloud Run delivers the load balancer's HTTP/2 to the container as plaintext HTTP/2 (port name
# h2c). Google requires a callout's Cloud Run service to allow unauthenticated invocation; the IAM invoker check is
# disabled instead of granting allUsers, and ingress plus the disabled default URL keep other callers out.
resource "google_cloud_run_v2_service" "verifier" {
  name                 = "${local.name}-verifier"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  default_uri_disabled = true
  invoker_iam_disabled = true
  deletion_protection  = false
  labels               = local.labels

  template {
    service_account                  = google_service_account.verifier.email
    timeout                          = "30s"
    max_instance_request_concurrency = 80

    scaling {
      # Reduces cold starts; doesn't remove them (the cold path is timed live).
      min_instance_count = 1
      max_instance_count = var.verifier_max_instances
    }

    containers {
      image = var.verifier_image

      ports {
        name           = "h2c"
        container_port = 8080
      }

      env {
        name  = "DNSID_TRUSTED_GOVERNANCE"
        value = var.trusted_governance
      }

      env {
        name  = "DNSID_ATTESTATION_KEY"
        value = random_password.attestation_key.result
      }

      # CPU always allocated, set explicitly: with a resources block, an unset cpu_idle means false, and Cloud Run then
      # needs at least 512Mi.
      resources {
        cpu_idle = false
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }
}

# Demo Bank. The load balancer's serverless NEG presents no identity, so it too allows unauthenticated invocation, and
# ingress plus the disabled default URL restrict it to the load balancer.
resource "google_cloud_run_v2_service" "origin" {
  name                 = "${local.name}-origin"
  location             = var.region
  ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  default_uri_disabled = true
  invoker_iam_disabled = true
  deletion_protection  = false
  labels               = local.labels

  template {
    service_account                  = google_service_account.origin.email
    timeout                          = "10s"
    max_instance_request_concurrency = 80

    scaling {
      min_instance_count = 1
      max_instance_count = var.origin_max_instances
    }

    containers {
      image = var.origin_image

      ports {
        name           = "http1"
        container_port = 8080
      }

      env {
        name  = "DNSID_ATTESTATION_KEY"
        value = random_password.attestation_key.result
      }

      # CPU only during requests: Demo Bank does nothing between them, and Cloud Run refuses 256Mi with CPU always
      # allocated (an unset cpu_idle, once a resources block is present).
      resources {
        cpu_idle = true
        limits = {
          cpu    = "1"
          memory = "256Mi"
        }
      }
    }
  }
}

# ---------- serverless NEGs and backend services ----------

resource "google_compute_region_network_endpoint_group" "verifier" {
  name                  = "${local.name}-verifier-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.verifier.name
  }
}

resource "google_compute_region_network_endpoint_group" "origin" {
  name                  = "${local.name}-origin-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.origin.name
  }
}

# The callout backend: HTTP/2, as gRPC requires. Cloud CDN is off (a callout backend can't use it anyway).
resource "google_compute_backend_service" "verifier" {
  name                  = "${local.name}-callout"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTP2"
  enable_cdn            = false

  backend {
    group = google_compute_region_network_endpoint_group.verifier.id
  }
}

# Demo Bank's backend. Cloud CDN stays off: a cache hit would be served before the authorization extension runs.
resource "google_compute_backend_service" "origin" {
  name                  = "${local.name}-origin"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false

  backend {
    group = google_compute_region_network_endpoint_group.origin.id
  }

  log_config {
    enable      = true
    sample_rate = 1
  }
}

# Every path goes to Demo Bank unchanged: no host or path rules, no redirects, no URL rewrites (a rewrite runs after the
# extension, so the origin would see a different path from the one verified).
resource "google_compute_url_map" "edge" {
  name            = "${local.name}-urlmap"
  default_service = google_compute_backend_service.origin.id
}

# ---------- the self-signed certificate for the reserved address ----------

resource "tls_private_key" "edge" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# Issued for the reserved IP address only. A test client trusts exactly this certificate (scripts/deploy.sh records it
# and its SHA-256 fingerprint in DEPLOY_OUT); nothing is told to skip verification.
resource "tls_self_signed_cert" "edge" {
  private_key_pem       = tls_private_key.edge.private_key_pem
  ip_addresses          = [var.address]
  validity_period_hours = 168

  subject {
    common_name  = var.address
    organization = "DNSid Google Cloud quick start (${local.name})"
  }

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "google_compute_ssl_certificate" "edge" {
  name        = "${local.name}-cert"
  certificate = tls_self_signed_cert.edge.cert_pem
  private_key = tls_private_key.edge.private_key_pem
}

# ---------- the load balancer front end: HTTPS only ----------

resource "google_compute_target_https_proxy" "edge" {
  name             = "${local.name}-https-proxy"
  url_map          = google_compute_url_map.edge.id
  ssl_certificates = [google_compute_ssl_certificate.edge.id]
}

# The deployment's only forwarding rule. There is no port-80 rule: plain HTTP doesn't reach anything.
resource "google_compute_global_forwarding_rule" "https" {
  name                  = "${local.name}-https"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"
  port_range            = "443"
  ip_address            = var.address
  target                = google_compute_target_https_proxy.edge.id
  labels                = local.labels
}

# ---------- the authorization extension and the policy that puts it in the request path ----------

# forward_headers is left unset, so every request header reaches the verifier: the signature may cover any field, and
# every caller-supplied x-dnsid-* header must be seen to be removed. fail_open = false: a callout that fails or times out
# blocks the request with the load balancer's own 500 (README.md, Security model and known limitations).
resource "google_network_services_authz_extension" "dnsid" {
  name                  = "${local.name}-authz"
  location              = "global"
  description           = "DNSid verification for deployment ${local.name}"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  service               = google_compute_backend_service.verifier.self_link
  authority             = "verifier.${local.name}.dnsid.internal"
  timeout               = "3s"
  fail_open             = false
  labels                = local.labels
}

# The extension enforces nothing until this policy names it and targets the forwarding rule. No http_rules: it applies
# to every request on the rule.
resource "google_network_security_authz_policy" "dnsid" {
  name        = "${local.name}-authz-policy"
  location    = "global"
  description = "Every request on ${google_compute_global_forwarding_rule.https.name} goes through DNSid verification"
  action      = "CUSTOM"
  labels      = local.labels

  target {
    load_balancing_scheme = "EXTERNAL_MANAGED"
    resources             = [google_compute_global_forwarding_rule.https.self_link]
  }

  custom_provider {
    authz_extension {
      resources = [google_network_services_authz_extension.dnsid.id]
    }
  }
}
