// The load balancer configuration the bypass cases depend on, read from Google's API listings (gcloud --format=json),
// and the checks made on it: every forwarding rule that can reach Demo Bank is a target of the DNSid CUSTOM
// authorization policy (deny-bypass-uncovered-rule), the deployment's URL map rewrites nothing and routes only to Demo
// Bank (deny-bypass-rewrite), and Cloud CDN is off on every backend in front of Demo Bank (deny-cache-reuse). "Can
// reach Demo Bank" is decided by each network endpoint group's destination (Cloud Run service and region, URL mask), not
// by which NEG the deployment created; a destination that can't be resolved counts as reaching it.
// No dependencies.

import type {
  BackendServiceRecord,
  ForwardingRuleRecord,
  Inventory,
  NegRecord,
  PolicyRecord,
  ProxyRecord,
  UrlMapRecord,
} from './deploy-out.ts';

type Json = unknown;

const str = (value: Json): string => (typeof value === 'string' ? value : '');
const list = (value: Json): Json[] => (Array.isArray(value) ? value : []);
const obj = (value: Json): Record<string, Json> => (typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, Json>) : {});

/**
 * A comparable key for a Google resource reference, whatever its form: a full self link, a relative name, with the
 * project's ID or number. The last segments name the kind, location and resource within one project, e.g.
 * `global/forwardingRules/x`, `regions/us-central1/networkEndpointGroups/y`, `locations/global/authzExtensions/z`.
 */
export function resourceKey(reference: string): string {
  const path = reference.replace(/^https:\/\/[^/]+\/(?:compute\/(?:v1|beta|alpha)\/)?/, '').replace(/^\/+/, '');
  const parts = path.split('/');
  const projectAt = parts.indexOf('projects');
  const rest = projectAt >= 0 ? parts.slice(projectAt + 2) : parts;
  return rest.join('/');
}

/** Every string value under keys that name a backend service, anywhere in a URL map. */
function servicesIn(value: Json, out: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) servicesIn(item, out);
    return;
  }
  const record = obj(value);
  for (const [key, inner] of Object.entries(record)) {
    if ((key === 'defaultService' || key === 'service' || key === 'backendService') && typeof inner === 'string') out.add(inner);
    else servicesIn(inner, out);
  }
}

/** Whether any rewrite, redirect or route action appears anywhere in a URL map. */
function rewritesIn(value: Json): boolean {
  if (Array.isArray(value)) return value.some(rewritesIn);
  const record = obj(value);
  return Object.entries(record).some(
    ([key, inner]) => ['urlRewrite', 'defaultUrlRedirect', 'urlRedirect', 'defaultRouteAction', 'routeAction'].includes(key) || rewritesIn(inner),
  );
}

export interface Listings {
  readonly forwardingRules: Json;
  readonly httpsProxies: Json;
  readonly httpProxies: Json;
  readonly urlMaps: Json;
  readonly backendServices: Json;
  /** Absent only for a caller that never listed them; see Inventory.negs. */
  readonly negs?: Json;
  readonly policies: Json;
}

/** Reduces the raw listings to the inventory recorded in DEPLOY_OUT and checked by the live tests. */
export function inventoryFrom(listings: Listings, source: string, takenAt: string): Inventory {
  const forwardingRules: ForwardingRuleRecord[] = list(listings.forwardingRules).map((r) => {
    const rule = obj(r);
    return {
      name: str(rule['name']),
      selfLink: str(rule['selfLink']),
      target: str(rule['target']),
      ipAddress: str(rule['IPAddress']),
      portRange: str(rule['portRange']),
      loadBalancingScheme: str(rule['loadBalancingScheme']),
    };
  });
  const proxies: ProxyRecord[] = [...list(listings.httpsProxies), ...list(listings.httpProxies)].map((p) => ({
    selfLink: str(obj(p)['selfLink']),
    urlMap: str(obj(p)['urlMap']),
  }));
  const urlMaps: UrlMapRecord[] = list(listings.urlMaps).map((m) => {
    const services = new Set<string>();
    servicesIn(m, services);
    return {
      selfLink: str(obj(m)['selfLink']),
      defaultService: str(obj(m)['defaultService']),
      services: [...services].sort(),
      rewrites: rewritesIn(m),
    };
  });
  const backendServices: BackendServiceRecord[] = list(listings.backendServices).map((b) => ({
    selfLink: str(obj(b)['selfLink']),
    enableCdn: obj(b)['enableCDN'] === true,
    protocol: str(obj(b)['protocol']),
    groups: list(obj(b)['backends']).map((backend) => str(obj(backend)['group'])),
  }));
  const negs: NegRecord[] = list(listings.negs).map((n) => {
    const neg = obj(n);
    const run = obj(neg['cloudRun']);
    const fn = obj(neg['cloudFunction']);
    const deployment = obj(neg['serverlessDeployment']);
    return {
      selfLink: str(neg['selfLink']),
      type: str(neg['networkEndpointType']),
      region: str(neg['region']).split('/').pop() ?? '',
      cloudRun: { service: str(run['service']), tag: str(run['tag']), urlMask: str(run['urlMask']) },
      cloudFunction: { function: str(fn['function']), urlMask: str(fn['urlMask']) },
      serverlessDeployment: { platform: str(deployment['platform']), resource: str(deployment['resource']), urlMask: str(deployment['urlMask']) },
      appEngine: neg['appEngine'] !== undefined,
    };
  });
  const policies: PolicyRecord[] = list(listings.policies).map((p) => {
    const policy = obj(p);
    return {
      name: str(policy['name']),
      action: str(policy['action']),
      targets: list(obj(policy['target'])['resources']).map(str),
      extensions: list(obj(obj(policy['customProvider'])['authzExtension'])['resources']).map(str),
      // gcloud's JSON leaves an empty list out; a present value that isn't a list is counted as a rule, so it restricts.
      httpRules: policy['httpRules'] === undefined ? 0 : Array.isArray(policy['httpRules']) ? policy['httpRules'].length : 1,
    };
  });
  const inventory = { takenAt, source, forwardingRules, proxies, urlMaps, backendServices, policies };
  return listings.negs === undefined ? inventory : { ...inventory, negs };
}

export interface DeploymentRefs {
  readonly forwardingRule: string;
  readonly urlMap: string;
  readonly originBackendService: string;
  readonly originNeg: string;
  /** Demo Bank's Cloud Run service name and region: what a NEG must name to reach it. */
  readonly originService: string;
  readonly originRegion: string;
  readonly authzExtension: string;
  readonly address: string;
}

export interface Finding {
  readonly pass: boolean;
  readonly detail: string;
}

/**
 * Where a NEG sends requests, with respect to Demo Bank: `origin` (it names Demo Bank's service in its region),
 * `unresolved` (it might: a URL mask, or a serverless NEG naming no destination this code knows), or `unrelated`.
 * Demo Bank's ingress admits only Cloud Load Balancing and its default URL is disabled, so only a serverless NEG in
 * Demo Bank's region can reach it (https://docs.cloud.google.com/load-balancing/docs/negs/serverless-neg-concepts);
 * a revision tag still reaches the same service, and a Cloud Run functions (2nd gen) function is a Cloud Run service.
 */
export function negReach(neg: NegRecord, refs: DeploymentRefs): 'origin' | 'unresolved' | 'unrelated' {
  if (resourceKey(neg.selfLink) === resourceKey(refs.originNeg)) return 'origin';
  if (neg.type !== 'SERVERLESS') return 'unrelated';
  if (neg.region !== refs.originRegion) return 'unrelated';
  const named = (value: string) => (value === refs.originService ? 'origin' : 'unrelated');
  if (neg.cloudRun.service !== '') return named(neg.cloudRun.service);
  if (neg.cloudFunction.function !== '') return named(neg.cloudFunction.function);
  if (neg.serverlessDeployment.platform !== '') {
    if (neg.serverlessDeployment.platform !== 'run.googleapis.com') return 'unrelated';
    if (neg.serverlessDeployment.resource !== '') return named(neg.serverlessDeployment.resource);
    return 'unresolved';
  }
  if (neg.appEngine) return 'unrelated';
  return 'unresolved';
}

interface Reach {
  /** Backend services (keys) that can send requests to Demo Bank. */
  readonly backends: Set<string>;
  /** NEGs counted as reaching Demo Bank: by destination, or because it couldn't be resolved. */
  readonly byDestination: string[];
  readonly unresolved: string[];
}

/**
 * The backend services that can send requests to Demo Bank: every one with a backend group that is a NEG reaching it
 * (negReach), or a NEG the inventory doesn't describe (unknown destination). Instance groups can't reach a Cloud Run
 * service. The deployment's own NEG always counts.
 */
function originReach(inventory: Inventory, refs: DeploymentRefs): Reach {
  const negs = new Map((inventory.negs ?? []).map((n) => [resourceKey(n.selfLink), n]));
  const own = resourceKey(refs.originNeg);
  const byDestination = new Set<string>();
  const unresolved = new Set<string>();
  const reaches = (group: string): boolean => {
    const key = resourceKey(group);
    if (key === own) return true;
    if (!/(^|\/)networkEndpointGroups\//.test(key)) return false;
    const neg = negs.get(key);
    const reach = neg === undefined ? 'unresolved' : negReach(neg, refs);
    if (reach === 'origin') byDestination.add(key);
    if (reach === 'unresolved') unresolved.add(key);
    return reach !== 'unrelated';
  };
  const backends = new Set(inventory.backendServices.filter((b) => b.groups.map(reaches).includes(true)).map((b) => resourceKey(b.selfLink)));
  return { backends, byDestination: [...byDestination].sort(), unresolved: [...unresolved].sort() };
}

const reachDetail = (reach: Reach) =>
  `other NEGs reaching Demo Bank by destination: ${reach.byDestination.join(', ') || 'none'}; ` +
  `NEGs with a destination that couldn't be resolved, counted as reaching it: ${reach.unresolved.join(', ') || 'none'}`;

/**
 * ADD-03: every forwarding rule that can reach Demo Bank is a target of a CUSTOM policy naming the DNSid extension and
 * having no HTTP rules. A CUSTOM policy's HTTP rules decide which requests reach its extension; with none, every request
 * does (https://docs.cloud.google.com/load-balancing/docs/auth-policy/auth-policy-overview). A policy with any rule, or
 * whose rules weren't recorded, covers only some requests at best, so it is not counted.
 */
export function checkCoverage(inventory: Inventory, refs: DeploymentRefs): Finding {
  const reach = originReach(inventory, refs);
  const backends = reach.backends;
  if (!backends.has(resourceKey(refs.originBackendService))) {
    return { pass: false, detail: "the inventory doesn't show the deployment's own Demo Bank backend service using its NEG" };
  }
  const maps = new Set(inventory.urlMaps.filter((m) => m.services.some((s) => backends.has(resourceKey(s)))).map((m) => resourceKey(m.selfLink)));
  const proxies = new Set(inventory.proxies.filter((p) => maps.has(resourceKey(p.urlMap))).map((p) => resourceKey(p.selfLink)));
  const reaching = inventory.forwardingRules.filter((r) => proxies.has(resourceKey(r.target)));
  const extension = resourceKey(refs.authzExtension);
  const dnsid = inventory.policies.filter((p) => p.action === 'CUSTOM' && p.extensions.some((e) => resourceKey(e) === extension));
  const unconditional = dnsid.filter((p) => p.httpRules === 0);
  const restricted = dnsid.filter((p) => p.httpRules !== 0);
  const covered = new Set(unconditional.flatMap((p) => p.targets.map(resourceKey)));
  const uncovered = reaching.filter((r) => !covered.has(resourceKey(r.selfLink)));
  const own = reaching.some((r) => resourceKey(r.selfLink) === resourceKey(refs.forwardingRule));
  const onAddress = inventory.forwardingRules.filter((r) => r.ipAddress === refs.address);
  const extraOnAddress = onAddress.filter((r) => resourceKey(r.selfLink) !== resourceKey(refs.forwardingRule));
  const names = (rules: readonly ForwardingRuleRecord[]) => rules.map((r) => `${r.name}:${r.portRange}`).join(', ') || 'none';
  const detail =
    `${inventory.forwardingRules.length} forwarding rule(s) in the project, ${reaching.length} reaching Demo Bank (${names(reaching)}), ` +
    `${uncovered.length} not covered by the DNSid policy (${names(uncovered)}); ` +
    `DNSid CUSTOM policies: ${dnsid.length}, not counted for having HTTP rules or none recorded: ${restricted.map((p) => `${p.name} (${p.httpRules ?? 'unrecorded'})`).join(', ') || 'none'}; ` +
    `rules on ${refs.address}: ${names(onAddress)}; ` +
    `${reachDetail(reach)}; ` +
    `inventory from ${inventory.source} at ${inventory.takenAt}`;
  return { pass: own && uncovered.length === 0 && extraOnAddress.length === 0, detail };
}

/** The deployment's URL map rewrites, redirects and route-acts nothing, and routes only to Demo Bank's backend. */
export function checkNoRewrite(inventory: Inventory, refs: DeploymentRefs): Finding {
  const map = inventory.urlMaps.find((m) => resourceKey(m.selfLink) === resourceKey(refs.urlMap));
  if (map === undefined) return { pass: false, detail: "the deployment's URL map is not in the inventory" };
  const others = map.services.filter((s) => resourceKey(s) !== resourceKey(refs.originBackendService));
  return {
    pass: !map.rewrites && others.length === 0 && resourceKey(map.defaultService) === resourceKey(refs.originBackendService),
    detail: `URL map rewrites/redirects/route actions: ${map.rewrites ? 'present' : 'none'}; services: ${map.services.map(resourceKey).join(', ')}; inventory from ${inventory.source} at ${inventory.takenAt}`,
  };
}

/** Cloud CDN is off on every backend service that can send requests to Demo Bank. */
export function checkNoCdn(inventory: Inventory, refs: DeploymentRefs): Finding {
  const reach = originReach(inventory, refs);
  const records = inventory.backendServices.filter((b) => reach.backends.has(resourceKey(b.selfLink)));
  const withCdn = records.filter((b) => b.enableCdn);
  return {
    pass: records.length > 0 && withCdn.length === 0,
    detail: `${records.length} backend service(s) in front of Demo Bank, Cloud CDN on ${withCdn.length}${withCdn.length ? ` (${withCdn.map((b) => resourceKey(b.selfLink)).join(', ')})` : ''}; ${reachDetail(reach)}; inventory from ${inventory.source} at ${inventory.takenAt}`,
  };
}
