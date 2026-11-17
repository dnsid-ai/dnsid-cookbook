// TEST ONLY. Fixtures for the deployment scripts' tests: Terraform outputs of both stages in `terraform output -json`
// form, DEPLOY_OUT inputs, and the Compute API listings of a project holding the deployment and one unrelated load
// balancer. Placeholder values throughout (documentation addresses 203.0.113.0/24 and 198.51.100.0/24, a made-up project).

import type { DeploymentRefs } from '../../scripts/lib/inventory.ts';

export const FAKE_SELF = 'https://www.googleapis.com/compute/v1/projects/sandbox-project-1';

export function stageOutputs(certificatePem: string, endpoint = 'https://203.0.113.10') {
  const v = (value: unknown) => ({ value, type: 'string', sensitive: false });
  const name = 'dnsid-gse-0a1b2c3d';
  const bootstrap = {
    deployment_name: v(name),
    project_id: v('sandbox-project-1'),
    project_number: v('123456789012'),
    region: v('us-central1'),
    address_name: v(`${name}-ip`),
    address: v('203.0.113.10'),
    address_self_link: v(`${FAKE_SELF}/global/addresses/${name}-ip`),
    repository_id: v(name),
    repository_url: v(`us-central1-docker.pkg.dev/sandbox-project-1/${name}`),
    build_bucket: v(`${name}-build`),
    build_service_account: v(`${name}-build@sandbox-project-1.iam.gserviceaccount.com`),
    build_service_account_id: v(`projects/sandbox-project-1/serviceAccounts/${name}-build@sandbox-project-1.iam.gserviceaccount.com`),
    enabled_services: v(['compute.googleapis.com']),
  };
  const address = new URL(endpoint).hostname;
  const service = {
    endpoint: v(endpoint),
    address: v(address),
    certificate_pem: v(certificatePem),
    certificate_not_after: v('2026-11-19T00:00:00Z'),
    forwarding_rule: v(`${FAKE_SELF}/global/forwardingRules/${name}-https`),
    target_https_proxy: v(`${FAKE_SELF}/global/targetHttpsProxies/${name}-https-proxy`),
    url_map: v(`${FAKE_SELF}/global/urlMaps/${name}-urlmap`),
    ssl_certificate: v(`${FAKE_SELF}/global/sslCertificates/${name}-cert`),
    origin_backend_service: v(`${FAKE_SELF}/global/backendServices/${name}-origin`),
    callout_backend_service: v(`${FAKE_SELF}/global/backendServices/${name}-callout`),
    origin_neg: v(`${FAKE_SELF}/regions/us-central1/networkEndpointGroups/${name}-origin-neg`),
    verifier_neg: v(`${FAKE_SELF}/regions/us-central1/networkEndpointGroups/${name}-verifier-neg`),
    authz_extension: v(`projects/sandbox-project-1/locations/global/authzExtensions/${name}-authz`),
    authz_policy: v(`projects/sandbox-project-1/locations/global/authzPolicies/${name}-authz-policy`),
    verifier_service: v(`${name}-verifier`),
    origin_service: v(`${name}-origin`),
    verifier_uri: v(''),
    origin_uri: v(''),
    verifier_urls: v([]),
    origin_urls: v([]),
    verifier_service_account: v(`${name}-verifier@sandbox-project-1.iam.gserviceaccount.com`),
    origin_service_account: v(`${name}-origin@sandbox-project-1.iam.gserviceaccount.com`),
    verifier_scaling: v({ min: 1, max: 3 }),
  };
  return { bootstrap, service };
}

export const DIGEST_V = `sha256:${'1'.repeat(64)}`;
export const DIGEST_O = `sha256:${'2'.repeat(64)}`;

export function deployOutInputs(certificatePem: string, endpoint?: string) {
  const { bootstrap, service } = stageOutputs(certificatePem, endpoint);
  return {
    bootstrap,
    service,
    images: {
      verifier: `us-central1-docker.pkg.dev/sandbox-project-1/dnsid-gse-0a1b2c3d/verifier@${DIGEST_V}`,
      origin: `us-central1-docker.pkg.dev/sandbox-project-1/dnsid-gse-0a1b2c3d/origin@${DIGEST_O}`,
    },
    inventory: { error: 'not taken', takenAt: '2026-11-12T00:00:00Z' },
    timing: { total_s: 1 },
    governance: 'dnsid-sandbox.io',
  };
}

export const N = 'dnsid-gse-0a1b2c3d';
export const REFS: DeploymentRefs = {
  forwardingRule: `${FAKE_SELF}/global/forwardingRules/${N}-https`,
  urlMap: `${FAKE_SELF}/global/urlMaps/${N}-urlmap`,
  originBackendService: `${FAKE_SELF}/global/backendServices/${N}-origin`,
  originNeg: `${FAKE_SELF}/regions/us-central1/networkEndpointGroups/${N}-origin-neg`,
  originService: `${N}-origin`,
  originRegion: 'us-central1',
  authzExtension: `projects/sandbox-project-1/locations/global/authzExtensions/${N}-authz`,
  address: '203.0.113.10',
};

/** What gcloud lists for the deployment alone, in the Compute API's JSON shape. */
export function deploymentListings() {
  return {
    forwardingRules: [
      { name: `${N}-https`, selfLink: REFS.forwardingRule, target: `${FAKE_SELF}/global/targetHttpsProxies/${N}-https-proxy`, IPAddress: '203.0.113.10', portRange: '443-443', loadBalancingScheme: 'EXTERNAL_MANAGED' },
      { name: 'unrelated', selfLink: `${FAKE_SELF}/global/forwardingRules/unrelated`, target: `${FAKE_SELF}/global/targetHttpProxies/unrelated`, IPAddress: '198.51.100.1', portRange: '80-80', loadBalancingScheme: 'EXTERNAL_MANAGED' },
    ],
    httpsProxies: [{ selfLink: `${FAKE_SELF}/global/targetHttpsProxies/${N}-https-proxy`, urlMap: REFS.urlMap }],
    httpProxies: [{ selfLink: `${FAKE_SELF}/global/targetHttpProxies/unrelated`, urlMap: `${FAKE_SELF}/global/urlMaps/unrelated` }],
    urlMaps: [
      { selfLink: REFS.urlMap, defaultService: REFS.originBackendService },
      { selfLink: `${FAKE_SELF}/global/urlMaps/unrelated`, defaultService: `${FAKE_SELF}/global/backendServices/unrelated` },
    ],
    backendServices: [
      { selfLink: REFS.originBackendService, enableCDN: false, protocol: 'HTTP', backends: [{ group: REFS.originNeg }] },
      { selfLink: `${FAKE_SELF}/global/backendServices/${N}-callout`, enableCDN: false, protocol: 'HTTP2', backends: [{ group: `${FAKE_SELF}/regions/us-central1/networkEndpointGroups/${N}-verifier-neg` }] },
      { selfLink: `${FAKE_SELF}/global/backendServices/unrelated`, enableCDN: true, protocol: 'HTTP', backends: [{ group: `${FAKE_SELF}/zones/a/instanceGroups/x` }] },
    ],
    negs: [
      { selfLink: REFS.originNeg, networkEndpointType: 'SERVERLESS', region: `${FAKE_SELF}/regions/us-central1`, cloudRun: { service: `${N}-origin` } },
      { selfLink: `${FAKE_SELF}/regions/us-central1/networkEndpointGroups/${N}-verifier-neg`, networkEndpointType: 'SERVERLESS', region: `${FAKE_SELF}/regions/us-central1`, cloudRun: { service: `${N}-verifier` } },
    ] as Record<string, unknown>[],
    policies: [
      {
        name: `projects/sandbox-project-1/locations/global/authzPolicies/${N}-authz-policy`,
        action: 'CUSTOM',
        target: { loadBalancingScheme: 'EXTERNAL_MANAGED', resources: [REFS.forwardingRule] },
        customProvider: { authzExtension: { resources: [`projects/123456789012/locations/global/authzExtensions/${N}-authz`] } },
      },
    ],
  };
}
