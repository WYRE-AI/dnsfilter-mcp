/**
 * DNSFilter authenticates with a static API key, generated in the DNSFilter
 * dashboard under Account Settings -> Security -> API Keys (an account
 * supports up to 5 active keys). Unlike most sibling WYRE Conduit
 * connectors, the key is sent as the RAW header value - `Authorization:
 * <key>`, no `Bearer` prefix - per DNSFilter's own API docs (api.dnsfilter.
 * com/docs, info.description): "Authentication is done by setting the
 * Authorization request header. The header value is the API key itself.
 * For example: Authorization: eyJ...". See README's Authentication section.
 */
export interface DNSFilterCredentials {
  apiKey: string;
}

/** Thrown when DNSFilter rejects the API key (HTTP 401) - distinct from rate limiting so callers get an honest error. */
export class DNSFilterAuthError extends Error {}

/** Thrown when DNSFilter rate-limits the request (HTTP 429) - distinct from an auth failure. */
export class DNSFilterRateLimitError extends Error {}

/** Thrown for any other non-2xx / unexpected vendor response. */
export class DNSFilterApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
  }
}

/**
 * V1 nested pagination, per DNSFilter's own docs (info.description):
 * passed in the query string as `page[number]=1&page[size]=10`. Every V1
 * list endpoint that supports paging takes this same shape.
 */
export interface PageParam {
  number?: number;
  size?: number;
}

export interface PageParams {
  page?: PageParam;
}

// ---------------------------------------------------------------------
// Organizations
// ---------------------------------------------------------------------

export interface ListOrganizationsParams extends PageParams {
  basic_info?: boolean;
  exclude_inherit_privacy_mode?: boolean;
  managed_by_msp_id?: number;
  name?: string;
  owned_msp_id?: number;
  pii_grid_search?: string;
  type?: 'normal' | 'msp' | 'sub_organization';
}

export interface GetOrganizationParams {
  id: number;
  include_current_mrr?: boolean;
}

export interface GetOrganizationSettingsParams {
  msp_id?: number;
  name?: string;
  organization_id?: number;
  organization_ids?: string;
}

// ---------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------

export interface ListNetworksParams extends PageParams {
  basic_info?: boolean;
  count_network_ips?: boolean;
  force_truncate_ips?: boolean;
  protected?: boolean;
  search?: string;
  unprotected?: boolean;
}

export interface GetNetworkParams {
  id: number;
  count_network_ips?: boolean;
}

export interface LookupNetworkByIpParams {
  requesting_ip_address: string;
}

// ---------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------

export interface ListPoliciesParams extends PageParams {
  include_global_policies?: boolean;
  organization_id?: number;
}

export interface GetPolicyParams {
  id: number;
  include_relationships?: boolean;
}

export interface GetApplicationPoliciesParams {
  application_id: number;
  organization_id: number;
  name?: string;
  policy_ids?: number[];
}

export interface GetPolicyPermissiveModeParams {
  id: number;
}

// ---------------------------------------------------------------------
// Categories
// ---------------------------------------------------------------------

export interface ListCategoriesParams extends PageParams {}

export interface ListApplicationCategoriesParams extends PageParams {}

// ---------------------------------------------------------------------
// Block Pages
// ---------------------------------------------------------------------

export interface ListBlockPagesParams extends PageParams {
  organization_id?: number;
}

export interface GetBlockPageParams {
  id: number;
  include_relationships?: boolean;
}

// ---------------------------------------------------------------------
// Metrics (organization usage)
// ---------------------------------------------------------------------

export interface GetOrganizationUsageParams {
  id: number;
  from: string;
  to: string;
}

// ---------------------------------------------------------------------
// Traffic Reports
// ---------------------------------------------------------------------

/**
 * Shared query-parameter shape across nearly every /v1/traffic_reports/*
 * endpoint. Every field is optional at the type level because each
 * individual DNSFilter report endpoint accepts a different subset (see
 * each tool's own JSDoc and inputSchema for the exact subset that
 * endpoint documents) - none of these are required by any report
 * endpoint except total_requests_geo's `limit`, modeled separately below.
 * Every *_ids field is a DNSFilter-documented COMMA-SEPARATED STRING, not
 * a JSON array - e.g. "Comma separated list of user agent UUIDs, defaults
 * to all" (agent_ids). Passed straight through, unmodified.
 */
export interface TrafficReportParams extends PageParams {
  agent_id?: string;
  agent_ids?: string;
  agent_types?: string;
  application_category_ids?: string;
  application_ids?: string;
  bucket_size?: string;
  category_ids?: string;
  collection_id?: string;
  collection_ids?: string;
  domain?: string;
  exclude_category_ids?: string;
  fqdn?: string;
  from?: string;
  limit?: number;
  mac_addresses?: string;
  msp_id?: number;
  name?: string;
  nat_ips?: string;
  network_id?: string;
  network_ids?: string;
  organization_id?: number;
  organization_ids?: string;
  policy_ids?: string;
  private_ip?: string;
  private_ip_from?: string;
  private_ip_to?: string;
  question_type?: string;
  result?: string;
  security_report?: 'all' | 'true' | 'false';
  show_individual_agents?: boolean;
  show_individual_collections?: boolean;
  show_individual_networks?: boolean;
  show_individual_organizations?: boolean;
  show_individual_users?: boolean;
  source?: 'all' | 'networks' | 'agents' | 'proxies';
  to?: string;
  type?: 'all' | 'allowed' | 'blocked';
  user_id?: string;
  user_ids?: string;
}

/** Generic JSON:API-ish envelope DNSFilter responses are passed through as-is. */
export interface DNSFilterResponse<T = unknown> {
  data?: T;
  included?: unknown[];
  links?: Record<string, unknown>;
  [key: string]: unknown;
}
