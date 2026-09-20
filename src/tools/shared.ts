import type { DNSFilterCredentials } from '../types.js';
import type { CallToolResult } from './types.js';

export function textResult(value: unknown): CallToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/** Returns an error CallToolResult if credentials are missing, else null. */
export function requireCredentials(creds: DNSFilterCredentials | null): CallToolResult | null {
  if (!creds) {
    return errorResult('No DNSFilter credentials configured. Set DNSFILTER_API_KEY.');
  }
  return null;
}

/** Shared input-schema fragment for the V1 nested-pagination list endpoints (every DNSFilter V1 list endpoint that pages). */
export const PAGE_PARAMS_PROPERTIES = {
  page: {
    type: 'object',
    description: "Pagination, e.g. { \"number\": 1, \"size\": 10 }. 'size' defaults to 10 (max 100).",
    properties: {
      number: { type: 'number', description: 'Page number (1-based). Defaults to 1.' },
      size: { type: 'number', description: 'Items per page (max 100). Defaults to 10.' },
    },
  },
} as const;

/**
 * Shared input-schema properties across the /v1/traffic_reports/* family.
 * Each individual report tool composes only the subset its own DNSFilter
 * endpoint actually documents (see each tool's inputSchema) - this object
 * is a lookup table of descriptions, not applied wholesale to every tool.
 */
export const TRAFFIC_REPORT_PROPERTIES = {
  from: {
    type: 'string',
    description:
      'Report UTC lower bound. Accepts YYYY-MM-DDThh:mm:ss[Z], YYYY-MM-DDThh:mm[Z], or a bare YYYY-MM-DD date (start of day). Defaults to 1 day ago.',
  },
  to: {
    type: 'string',
    description:
      'Report UTC upper bound. Accepts YYYY-MM-DDThh:mm:ss[Z], YYYY-MM-DDThh:mm[Z], or a bare YYYY-MM-DD date (end of day, inclusive). Defaults to now.',
  },
  organization_ids: {
    type: 'string',
    description: 'Comma-separated organization IDs. Defaults to the user organization ID. An inaccessible/unknown ID returns a 403.',
  },
  organization_id: { type: 'number', description: 'Organization ID.' },
  network_ids: { type: 'string', description: 'Comma-separated network (site) IDs. Defaults to all.' },
  network_id: { type: 'string', description: 'Comma-separated network (site) IDs. Defaults to all.' },
  agent_ids: { type: 'string', description: 'Comma-separated user-agent (client) UUIDs. Defaults to all.' },
  agent_id: { type: 'string', description: 'Comma-separated user-agent (client) UUIDs. Defaults to all.' },
  agent_types: { type: 'string', description: 'Comma-separated agent/client types.' },
  user_ids: { type: 'string', description: 'Comma-separated local user IDs. Defaults to all.' },
  user_id: { type: 'string', description: 'Comma-separated local user IDs. Defaults to all.' },
  mac_addresses: { type: 'string', description: 'Comma-separated MAC addresses to filter to.' },
  nat_ips: { type: 'string', description: 'Comma-separated NAT IP addresses to filter to.' },
  collection_ids: { type: 'string', description: 'Comma-separated collection (roaming-client group) IDs.' },
  collection_id: { type: 'string', description: 'Comma-separated collection (roaming-client group) IDs.' },
  application_ids: { type: 'string', description: 'Comma-separated application IDs to filter to.' },
  application_category_ids: { type: 'string', description: 'Comma-separated application category IDs to filter to.' },
  category_ids: { type: 'string', description: 'Comma-separated content-category IDs to filter to.' },
  exclude_category_ids: { type: 'string', description: 'Comma-separated content-category IDs to exclude.' },
  policy_ids: { type: 'string', description: 'Comma-separated policy IDs to filter to.' },
  domain: { type: 'string', description: 'Filter to a specific domain.' },
  fqdn: { type: 'string', description: 'Filter to a specific fully-qualified domain name.' },
  question_type: { type: 'string', description: 'Filter to a specific DNS question (record) type, e.g. A, AAAA, CNAME.' },
  result: { type: 'string', description: 'Filter to a specific query result.' },
  msp_id: { type: 'number', description: 'MSP ID to scope the report to.' },
  name: { type: 'string', description: 'Filter/search by name.' },
  private_ip: { type: 'string', description: 'Filter to a specific private/internal IP address.' },
  private_ip_from: { type: 'string', description: 'Lower bound of a private/internal IP address range.' },
  private_ip_to: { type: 'string', description: 'Upper bound of a private/internal IP address range.' },
  type: { type: 'string', enum: ['all', 'allowed', 'blocked'], description: 'Report type. Defaults to all.' },
  source: {
    type: 'string',
    enum: ['all', 'networks', 'agents', 'proxies'],
    description: 'Comma-separated traffic source. Defaults to all.',
  },
  security_report: {
    type: 'string',
    enum: ['all', 'true', 'false'],
    description: "Threat-only report. 'all' returns both threats and non-threats.",
  },
  bucket_size: {
    type: 'string',
    description:
      "Time-bucket size: 'auto' (default), '15min', or '1day'. Auto picks 15min for a <24h range and 1day for a >=24h range.",
  },
  limit: { type: 'number', description: 'Limit the number of results returned.' },
  show_individual_networks: { type: 'boolean', description: 'Group results by individual network ID. Defaults to false.' },
  show_individual_organizations: { type: 'boolean', description: 'Group results by individual organization ID. Defaults to false.' },
  show_individual_users: { type: 'boolean', description: 'Group results by individual local user ID. Defaults to false.' },
  show_individual_agents: { type: 'boolean', description: 'Group results by individual client/agent ID. Defaults to false.' },
  show_individual_collections: { type: 'boolean', description: 'Group results by individual collection ID. Defaults to false.' },
  ...PAGE_PARAMS_PROPERTIES,
} as const;

/** Builds a JSON-Schema `properties` object with only the given keys of TRAFFIC_REPORT_PROPERTIES, in the endpoint's own documented order. */
export function pickReportProperties(
  ...keys: (keyof typeof TRAFFIC_REPORT_PROPERTIES)[]
): Record<string, object> {
  const out: Record<string, object> = {};
  for (const key of keys) out[key] = TRAFFIC_REPORT_PROPERTIES[key];
  return out;
}
