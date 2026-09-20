import { AsyncLocalStorage } from 'node:async_hooks';
import { logger } from './utils/logger.js';
import { DNSFilterApiError, DNSFilterAuthError, DNSFilterRateLimitError } from './types.js';
import type {
  DNSFilterCredentials,
  DNSFilterResponse,
  GetApplicationPoliciesParams,
  GetBlockPageParams,
  GetNetworkParams,
  GetOrganizationParams,
  GetOrganizationSettingsParams,
  GetOrganizationUsageParams,
  GetPolicyParams,
  GetPolicyPermissiveModeParams,
  ListApplicationCategoriesParams,
  ListBlockPagesParams,
  ListCategoriesParams,
  ListNetworksParams,
  ListOrganizationsParams,
  ListPoliciesParams,
  LookupNetworkByIpParams,
  PageParam,
  TrafficReportParams,
} from './types.js';

export const BASE_URL = 'https://api.dnsfilter.com';

// Request-scoped credential store. In gateway mode the HTTP layer runs each
// request inside runWithCredentials({apiKey}); getCredentials() reads from
// it. Falls back to process.env for stdio/single-tenant mode.
const credStore = new AsyncLocalStorage<DNSFilterCredentials>();

export function runWithCredentials<T>(creds: DNSFilterCredentials, fn: () => T): T {
  return credStore.run(creds, fn);
}

export function getCredentials(): DNSFilterCredentials | null {
  const scoped = credStore.getStore();
  if (scoped?.apiKey) return scoped;
  const apiKey = process.env.DNSFILTER_API_KEY;
  if (!apiKey) {
    logger.warn('Missing credentials', { hasApiKey: !!apiKey });
    return null;
  }
  return { apiKey };
}

/** DNSFilter's V1 nested pagination is passed as `page[number]`/`page[size]` - see types.ts's PageParam doc. */
function appendPage(qs: URLSearchParams, page: PageParam | undefined): void {
  if (!page) return;
  if (page.number !== undefined) qs.append('page[number]', String(page.number));
  if (page.size !== undefined) qs.append('page[size]', String(page.size));
}

function buildQuery(params: Record<string, unknown> = {}): URLSearchParams {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (key === 'page') {
      appendPage(qs, value as PageParam);
      continue;
    }
    // Most DNSFilter list params that take multiple values are documented
    // as a single COMMA-SEPARATED STRING (e.g. traffic-report *_ids
    // filters - see TrafficReportParams' JSDoc), so a plain string just
    // passes through String(value) below. The one genuine array-typed
    // query param in this connector's surface (policies/application's
    // policy_ids: integer[]) needs real Rails-style repeated `key[]=`
    // pairs instead of a single stringified value.
    if (Array.isArray(value)) {
      for (const item of value) qs.append(`${key}[]`, String(item));
      continue;
    }
    qs.append(key, String(value));
  }
  return qs;
}

async function doGet<T>(
  creds: DNSFilterCredentials,
  path: string,
  query?: Record<string, unknown>
): Promise<T> {
  const qs = query ? buildQuery(query).toString() : '';
  const url = `${BASE_URL}${path}${qs ? `?${qs}` : ''}`;
  const res = await fetch(url, {
    method: 'GET',
    // No "Bearer" prefix - DNSFilter's own docs are explicit that the raw
    // key IS the header value ("Authorization: eyJ..."). See types.ts.
    headers: { Authorization: creds.apiKey, Accept: 'application/json' },
    signal: AbortSignal.timeout(15_000),
  });

  // 401 (invalid/revoked API key) and 429 (rate-limited) are distinct
  // failure modes with distinct remediations - grouping them under one
  // generic auth-error class hides a transient rate limit behind a message
  // that reads like a bad/expired key.
  if (res.status === 401) {
    throw new DNSFilterAuthError(`DNSFilter rejected the API key (HTTP 401): ${path}`);
  }
  if (res.status === 429) {
    throw new DNSFilterRateLimitError(`DNSFilter rate-limited the request (HTTP 429): ${path}`);
  }
  if (!res.ok) {
    throw new DNSFilterApiError(`DNSFilter ${path} failed: HTTP ${res.status}`, res.status);
  }
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------

/** GET /v1/organizations - list the organizations visible to this API key. */
export async function listOrganizations(
  creds: DNSFilterCredentials,
  params: ListOrganizationsParams = {}
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/organizations', { ...params });
}

/** GET /v1/organizations/{id} - basic information for one organization. */
export async function getOrganization(
  creds: DNSFilterCredentials,
  { id, ...params }: GetOrganizationParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/organizations/${encodeURIComponent(id)}`, { ...params });
}

/** GET /v1/organizations/settings - organization-level settings, optionally scoped by organization_id/msp_id. */
export async function getOrganizationSettings(
  creds: DNSFilterCredentials,
  params: GetOrganizationSettingsParams = {}
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/organizations/settings', { ...params });
}

// ---------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------

/** GET /v1/networks - list the networks (sites) visible to this API key. */
export async function listNetworks(
  creds: DNSFilterCredentials,
  params: ListNetworksParams = {}
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/networks', { ...params });
}

/** GET /v1/networks/{id} - basic information for one network. */
export async function getNetwork(
  creds: DNSFilterCredentials,
  { id, ...params }: GetNetworkParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/networks/${encodeURIComponent(id)}`, { ...params });
}

/** GET /v1/networks/lookup - find the network associated with a given IP address. */
export async function lookupNetworkByIp(
  creds: DNSFilterCredentials,
  params: LookupNetworkByIpParams
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/networks/lookup', { ...params });
}

/** GET /v1/networks/geo - every visible network's geo/location metadata only. */
export async function getNetworksGeo(creds: DNSFilterCredentials): Promise<DNSFilterResponse[]> {
  return doGet(creds, '/v1/networks/geo');
}

// ---------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------

/** GET /v1/policies - list filtering policies visible to this API key. */
export async function listPolicies(
  creds: DNSFilterCredentials,
  params: ListPoliciesParams = {}
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/policies', { ...params });
}

/** GET /v1/policies/{id} - a single policy's full configuration (allow/block lists, categories, applications). */
export async function getPolicy(
  creds: DNSFilterCredentials,
  { id, ...params }: GetPolicyParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/policies/${encodeURIComponent(id)}`, { ...params });
}

/** GET /v1/policies/application - which policies allow/block a given application, for an organization. */
export async function getApplicationPolicies(
  creds: DNSFilterCredentials,
  params: GetApplicationPoliciesParams
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/policies/application', { ...params });
}

/** GET /v1/policies/{id}/permissive_mode - whether a policy currently has permissive (monitor-only) mode enabled. */
export async function getPolicyPermissiveMode(
  creds: DNSFilterCredentials,
  { id }: GetPolicyPermissiveModeParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/policies/${encodeURIComponent(id)}/permissive_mode`);
}

// ---------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------

/** GET /v1/categories - list DNSFilter's content-filtering categories (used to build allow/block policy rules). */
export async function listCategories(
  creds: DNSFilterCredentials,
  params: ListCategoriesParams = {}
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/categories', { ...params });
}

/** GET /v1/categories/{id} - a single content category's details and hierarchy (parent/child categories). */
export async function getCategory(creds: DNSFilterCredentials, id: number): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/categories/${encodeURIComponent(id)}`);
}

/** GET /v1/application_categories - list application categories (used for the application-control surface of a policy). */
export async function listApplicationCategories(
  creds: DNSFilterCredentials,
  params: ListApplicationCategoriesParams = {}
): Promise<DNSFilterResponse> {
  return doGet(creds, '/v1/application_categories', { ...params });
}

/** GET /v1/application_categories/{id} - a single application category's details. */
export async function getApplicationCategory(
  creds: DNSFilterCredentials,
  id: number
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/application_categories/${encodeURIComponent(id)}`);
}

// ---------------------------------------------------------------------
// Block Pages
// ---------------------------------------------------------------------

/** GET /v1/block_pages - list the custom block pages configured for the current user/organization. */
export async function listBlockPages(
  creds: DNSFilterCredentials,
  params: ListBlockPagesParams = {}
): Promise<DNSFilterResponse[]> {
  return doGet(creds, '/v1/block_pages', { ...params });
}

/** GET /v1/block_pages/{id} - a single custom block page's configuration (branding, contact, appearance). */
export async function getBlockPage(
  creds: DNSFilterCredentials,
  { id, ...params }: GetBlockPageParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/block_pages/${encodeURIComponent(id)}`, { ...params });
}

// ---------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------

/** GET /v1/metrics/organization_usage/{id} - usage summary (plan, users, requests) for an organization over a date range (max 365 days). */
export async function getOrganizationUsage(
  creds: DNSFilterCredentials,
  { id, ...params }: GetOrganizationUsageParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/metrics/organization_usage/${encodeURIComponent(id)}`, { ...params });
}

/** GET /v1/metrics/organization_usage_detailed/{id} - the detailed (per-day/per-metric) breakdown of organization usage over a date range. */
export async function getOrganizationUsageDetailed(
  creds: DNSFilterCredentials,
  { id, ...params }: GetOrganizationUsageParams
): Promise<DNSFilterResponse> {
  return doGet(creds, `/v1/metrics/organization_usage_detailed/${encodeURIComponent(id)}`, { ...params });
}

// ---------------------------------------------------------------------
// Traffic Reports - the full documented GET-only reporting surface. Every
// function below wraps exactly one /v1/traffic_reports/* path; every
// parameter is optional and forwarded unmodified (see TrafficReportParams'
// JSDoc in types.ts). None of these endpoints mutate anything - DNSFilter
// only exposes reporting as reads.
// ---------------------------------------------------------------------

function trafficReport(
  path: string
): (creds: DNSFilterCredentials, params?: TrafficReportParams) => Promise<DNSFilterResponse> {
  return (creds, params = {}) => doGet(creds, `/v1/traffic_reports/${path}`, { ...params });
}

/** GET /v1/traffic_reports/qps - queries-per-second time series. */
export const getQps = trafficReport('qps');
/** GET /v1/traffic_reports/qps_active_agents - queries-per-second broken out by active client/agent. */
export const getQpsActiveAgents = trafficReport('qps_active_agents');
/** GET /v1/traffic_reports/qps_active_organizations - queries-per-second broken out by active organization. */
export const getQpsActiveOrganizations = trafficReport('qps_active_organizations');
/** GET /v1/traffic_reports/query_logs - raw DNS query log entries (domain, requester, category, allow/block result). */
export const getQueryLogs = trafficReport('query_logs');
/** GET /v1/traffic_reports/top_agents - clients/agents generating the most traffic. */
export const getTopAgents = trafficReport('top_agents');
/** GET /v1/traffic_reports/top_application_categories - application categories generating the most traffic. */
export const getTopApplicationCategories = trafficReport('top_application_categories');
/** GET /v1/traffic_reports/top_categories - content categories generating the most traffic. */
export const getTopCategories = trafficReport('top_categories');
/** GET /v1/traffic_reports/top_collections - collections (roaming-client groupings) generating the most traffic. */
export const getTopCollections = trafficReport('top_collections');
/** GET /v1/traffic_reports/top_domains - domains queried most often. */
export const getTopDomains = trafficReport('top_domains');
/** GET /v1/traffic_reports/top_networks - networks generating the most traffic. */
export const getTopNetworks = trafficReport('top_networks');
/** GET /v1/traffic_reports/top_organizations_requests - organizations generating the most request volume. */
export const getTopOrganizationsRequests = trafficReport('top_organizations_requests');
/** GET /v1/traffic_reports/top_users - local users generating the most traffic. */
export const getTopUsers = trafficReport('top_users');
/** GET /v1/traffic_reports/total_applications_agents_stats - application request counts broken out by client/agent. */
export const getTotalApplicationsAgentsStats = trafficReport('total_applications_agents_stats');
/** GET /v1/traffic_reports/total_applications_collections_stats - application request counts broken out by collection. */
export const getTotalApplicationsCollectionsStats = trafficReport('total_applications_collections_stats');
/** GET /v1/traffic_reports/total_applications_networks_stats - application request counts broken out by network. */
export const getTotalApplicationsNetworksStats = trafficReport('total_applications_networks_stats');
/** GET /v1/traffic_reports/total_applications_stats - total application request counts. */
export const getTotalApplicationsStats = trafficReport('total_applications_stats');
/** GET /v1/traffic_reports/total_applications_users_stats - application request counts broken out by local user. */
export const getTotalApplicationsUsersStats = trafficReport('total_applications_users_stats');
/** GET /v1/traffic_reports/total_categories - total content-category request counts over time. */
export const getTotalCategories = trafficReport('total_categories');
/** GET /v1/traffic_reports/total_categories_organizations - total content-category request counts broken out by organization. */
export const getTotalCategoriesOrganizations = trafficReport('total_categories_organizations');
/** GET /v1/traffic_reports/total_category_stats - content-category request-count summary. */
export const getTotalCategoryStats = trafficReport('total_category_stats');
/** GET /v1/traffic_reports/total_client_stats - client/agent count summary. */
export const getTotalClientStats = trafficReport('total_client_stats');
/** GET /v1/traffic_reports/total_deployments - deployed client/network counts. */
export const getTotalDeployments = trafficReport('total_deployments');
/** GET /v1/traffic_reports/total_domain_stats - single-domain request-count summary (use with the domain/fqdn filter). */
export const getTotalDomainStats = trafficReport('total_domain_stats');
/** GET /v1/traffic_reports/total_domains - total domain request counts over time. */
export const getTotalDomains = trafficReport('total_domains');
/** GET /v1/traffic_reports/total_domains_organizations - total domain request counts broken out by organization. */
export const getTotalDomainsOrganizations = trafficReport('total_domains_organizations');
/** GET /v1/traffic_reports/total_domains_users - total domain request counts broken out by local user. */
export const getTotalDomainsUsers = trafficReport('total_domains_users');
/** GET /v1/traffic_reports/total_organizations_requests - total request counts broken out by organization. */
export const getTotalOrganizationsRequests = trafficReport('total_organizations_requests');
/** GET /v1/traffic_reports/total_organizations_stats - organization-level request-count summary. */
export const getTotalOrganizationsStats = trafficReport('total_organizations_stats');
/** GET /v1/traffic_reports/total_requests - total DNS request counts over time. */
export const getTotalRequests = trafficReport('total_requests');
/** GET /v1/traffic_reports/total_requests_agents - total request counts broken out by client/agent. */
export const getTotalRequestsAgents = trafficReport('total_requests_agents');
/** GET /v1/traffic_reports/total_requests_collections - total request counts broken out by collection. */
export const getTotalRequestsCollections = trafficReport('total_requests_collections');
/** GET /v1/traffic_reports/total_requests_geo - total request counts broken out by geography. Requires `limit`. */
export const getTotalRequestsGeo = trafficReport('total_requests_geo');
/** GET /v1/traffic_reports/total_requests_organizations - total request counts broken out by organization. */
export const getTotalRequestsOrganizations = trafficReport('total_requests_organizations');
/** GET /v1/traffic_reports/total_requests_users - total request counts broken out by local user. */
export const getTotalRequestsUsers = trafficReport('total_requests_users');
/** GET /v1/traffic_reports/total_roaming_clients - count of roaming (off-network) clients. */
export const getTotalRoamingClients = trafficReport('total_roaming_clients');
/** GET /v1/traffic_reports/total_threats - total blocked-threat counts over time. */
export const getTotalThreats = trafficReport('total_threats');
/** GET /v1/traffic_reports/total_threats_organizations - total blocked-threat counts broken out by organization. */
export const getTotalThreatsOrganizations = trafficReport('total_threats_organizations');
/** GET /v1/traffic_reports/total_threats_users - total blocked-threat counts broken out by local user. */
export const getTotalThreatsUsers = trafficReport('total_threats_users');
