import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import * as client from '../client.js';
import { getCredentials } from '../client.js';
import type { DNSFilterCredentials, DNSFilterResponse, TrafficReportParams } from '../types.js';
import type { CallToolResult } from './types.js';
import { errorResult, pickReportProperties, requireCredentials, textResult } from './shared.js';

/**
 * One read-only tool per documented /v1/traffic_reports/* GET operation -
 * DNSFilter's entire reporting surface is GET-only (see README's Scope
 * section), so every tool below maps 1:1 to a real endpoint with no
 * curation. Every parameter is optional except total_requests_geo's
 * `limit`. Field descriptions live once in shared.ts's
 * TRAFFIC_REPORT_PROPERTIES and are composed per tool via
 * pickReportProperties() in each endpoint's own documented parameter
 * order, so a tool's inputSchema always matches what DNSFilter actually
 * accepts for that specific path.
 */
export const TRAFFIC_REPORT_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_get_qps',
    description: "Queries-per-second time series - the closest thing to a live traffic pulse.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'),
    },
  },
  {
    name: 'dnsfilter_get_qps_active_agents',
    description: "Queries-per-second broken out by active client/agent.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_qps_active_organizations',
    description: "Queries-per-second broken out by active organization.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_query_logs',
    description: "Raw DNS query log entries - domain queried, requester, category, and allow/block result. The most granular, PII-bearing report this connector exposes.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_id', 'network_ids', 'network_id', 'agent_ids', 'agent_id', 'user_ids', 'user_id', 'mac_addresses', 'nat_ips', 'collection_ids', 'collection_id', 'application_ids', 'application_category_ids', 'category_ids', 'exclude_category_ids', 'policy_ids', 'domain', 'fqdn', 'question_type', 'result', 'private_ip', 'private_ip_from', 'private_ip_to', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_agents',
    description: "Clients/agents generating the most traffic.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_application_categories',
    description: "Application categories generating the most traffic.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_categories',
    description: "Content categories generating the most traffic.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_collections',
    description: "Collections (roaming-client groupings) generating the most traffic.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_domains',
    description: "Domains queried most often.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'fqdn', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_networks',
    description: "Networks generating the most traffic.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_organizations_requests',
    description: "Organizations generating the most request volume.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_id', 'msp_id', 'bucket_size', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_top_users',
    description: "Local users generating the most traffic.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'),
    },
  },
  {
    name: 'dnsfilter_get_total_applications_agents_stats',
    description: "Application request counts broken out by client/agent.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_total_applications_collections_stats',
    description: "Application request counts broken out by collection.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_total_applications_networks_stats',
    description: "Application request counts broken out by network.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_total_applications_stats',
    description: "Total application request counts.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_total_applications_users_stats',
    description: "Application request counts broken out by local user.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'),
    },
  },
  {
    name: 'dnsfilter_get_total_categories',
    description: "Total content-category request counts over time.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'),
    },
  },
  {
    name: 'dnsfilter_get_total_categories_organizations',
    description: "Total content-category request counts broken out by organization.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_organizations'),
    },
  },
  {
    name: 'dnsfilter_get_total_category_stats',
    description: "Content-category request-count summary.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_id', 'network_ids', 'category_ids', 'msp_id'),
    },
  },
  {
    name: 'dnsfilter_get_total_client_stats',
    description: "Client/agent count summary.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_id', 'network_ids', 'msp_id'),
    },
  },
  {
    name: 'dnsfilter_get_total_deployments',
    description: "Deployed client/network counts.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('organization_id', 'network_ids', 'msp_id'),
    },
  },
  {
    name: 'dnsfilter_get_total_domain_stats',
    description: "Single-domain request-count summary - use with the domain/fqdn filter.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_id', 'network_ids', 'domain', 'fqdn', 'msp_id'),
    },
  },
  {
    name: 'dnsfilter_get_total_domains',
    description: "Total domain request counts over time.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'),
    },
  },
  {
    name: 'dnsfilter_get_total_domains_organizations',
    description: "Total domain request counts broken out by organization.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_organizations'),
    },
  },
  {
    name: 'dnsfilter_get_total_domains_users',
    description: "Total domain request counts broken out by local user.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_users'),
    },
  },
  {
    name: 'dnsfilter_get_total_organizations_requests',
    description: "Total request counts broken out by organization.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'organization_id', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'fqdn', 'msp_id', 'name', 'type', 'security_report', 'bucket_size'),
    },
  },
  {
    name: 'dnsfilter_get_total_organizations_stats',
    description: "Organization-level request-count summary.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_id', 'agent_ids', 'agent_types', 'user_ids', 'collection_ids', 'application_category_ids', 'msp_id', 'name', 'type', 'security_report', 'bucket_size'),
    },
  },
  {
    name: 'dnsfilter_get_total_requests',
    description: "Total DNS request counts over time.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'),
    },
  },
  {
    name: 'dnsfilter_get_total_requests_agents',
    description: "Total request counts broken out by client/agent.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_agents'),
    },
  },
  {
    name: 'dnsfilter_get_total_requests_collections',
    description: "Total request counts broken out by collection.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_collections'),
    },
  },
  {
    name: 'dnsfilter_get_total_requests_geo',
    description: "Total request counts broken out by geography.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'msp_id', 'limit'),
      required: ['limit'],
    },
  },
  {
    name: 'dnsfilter_get_total_requests_organizations',
    description: "Total request counts broken out by organization.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_organizations'),
    },
  },
  {
    name: 'dnsfilter_get_total_requests_users',
    description: "Total request counts broken out by local user.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_users'),
    },
  },
  {
    name: 'dnsfilter_get_total_roaming_clients',
    description: "Count of roaming (off-network) clients.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('organization_id', 'msp_id'),
    },
  },
  {
    name: 'dnsfilter_get_total_threats',
    description: "Total blocked-threat counts over time.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'bucket_size', 'show_individual_networks'),
    },
  },
  {
    name: 'dnsfilter_get_total_threats_organizations',
    description: "Total blocked-threat counts broken out by organization.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'bucket_size', 'show_individual_organizations'),
    },
  },
  {
    name: 'dnsfilter_get_total_threats_users',
    description: "Total blocked-threat counts broken out by local user.",
    inputSchema: {
      type: 'object',
      properties: pickReportProperties('from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'bucket_size', 'show_individual_users'),
    },
  },
];

const TOOL_NAMES = new Set(TRAFFIC_REPORT_TOOLS.map((t) => t.name));
export function isTrafficReportTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

/** Maps a dnsfilter_get_<suffix> tool name to its client.ts function, e.g. dnsfilter_get_top_domains -> client.getTopDomains. */
const CLIENT_FN: Record<
  string,
  (creds: DNSFilterCredentials, params?: TrafficReportParams) => Promise<DNSFilterResponse>
> = {
  dnsfilter_get_qps: client.getQps,
  dnsfilter_get_qps_active_agents: client.getQpsActiveAgents,
  dnsfilter_get_qps_active_organizations: client.getQpsActiveOrganizations,
  dnsfilter_get_query_logs: client.getQueryLogs,
  dnsfilter_get_top_agents: client.getTopAgents,
  dnsfilter_get_top_application_categories: client.getTopApplicationCategories,
  dnsfilter_get_top_categories: client.getTopCategories,
  dnsfilter_get_top_collections: client.getTopCollections,
  dnsfilter_get_top_domains: client.getTopDomains,
  dnsfilter_get_top_networks: client.getTopNetworks,
  dnsfilter_get_top_organizations_requests: client.getTopOrganizationsRequests,
  dnsfilter_get_top_users: client.getTopUsers,
  dnsfilter_get_total_applications_agents_stats: client.getTotalApplicationsAgentsStats,
  dnsfilter_get_total_applications_collections_stats: client.getTotalApplicationsCollectionsStats,
  dnsfilter_get_total_applications_networks_stats: client.getTotalApplicationsNetworksStats,
  dnsfilter_get_total_applications_stats: client.getTotalApplicationsStats,
  dnsfilter_get_total_applications_users_stats: client.getTotalApplicationsUsersStats,
  dnsfilter_get_total_categories: client.getTotalCategories,
  dnsfilter_get_total_categories_organizations: client.getTotalCategoriesOrganizations,
  dnsfilter_get_total_category_stats: client.getTotalCategoryStats,
  dnsfilter_get_total_client_stats: client.getTotalClientStats,
  dnsfilter_get_total_deployments: client.getTotalDeployments,
  dnsfilter_get_total_domain_stats: client.getTotalDomainStats,
  dnsfilter_get_total_domains: client.getTotalDomains,
  dnsfilter_get_total_domains_organizations: client.getTotalDomainsOrganizations,
  dnsfilter_get_total_domains_users: client.getTotalDomainsUsers,
  dnsfilter_get_total_organizations_requests: client.getTotalOrganizationsRequests,
  dnsfilter_get_total_organizations_stats: client.getTotalOrganizationsStats,
  dnsfilter_get_total_requests: client.getTotalRequests,
  dnsfilter_get_total_requests_agents: client.getTotalRequestsAgents,
  dnsfilter_get_total_requests_collections: client.getTotalRequestsCollections,
  dnsfilter_get_total_requests_geo: client.getTotalRequestsGeo,
  dnsfilter_get_total_requests_organizations: client.getTotalRequestsOrganizations,
  dnsfilter_get_total_requests_users: client.getTotalRequestsUsers,
  dnsfilter_get_total_roaming_clients: client.getTotalRoamingClients,
  dnsfilter_get_total_threats: client.getTotalThreats,
  dnsfilter_get_total_threats_organizations: client.getTotalThreatsOrganizations,
  dnsfilter_get_total_threats_users: client.getTotalThreatsUsers,
};

/**
 * Per-tool allowed parameter keys, taken from each tool's own inputSchema
 * above (which itself comes from that specific DNSFilter endpoint's
 * documented parameter list) - so a call only ever forwards params the
 * target endpoint actually documents, never leaking an unrelated field
 * from a caller-supplied args object into a different report's request.
 */
const TOOL_PARAM_KEYS: Record<string, readonly string[]> = {
  dnsfilter_get_qps: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'],
  dnsfilter_get_qps_active_agents: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_qps_active_organizations: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_query_logs: ['from', 'to', 'organization_id', 'network_ids', 'network_id', 'agent_ids', 'agent_id', 'user_ids', 'user_id', 'mac_addresses', 'nat_ips', 'collection_ids', 'collection_id', 'application_ids', 'application_category_ids', 'category_ids', 'exclude_category_ids', 'policy_ids', 'domain', 'fqdn', 'question_type', 'result', 'private_ip', 'private_ip_from', 'private_ip_to', 'source', 'security_report', 'page'],
  dnsfilter_get_top_agents: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_top_application_categories: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_top_categories: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_top_collections: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_top_domains: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'fqdn', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_top_networks: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_top_organizations_requests: ['from', 'to', 'organization_id', 'msp_id', 'bucket_size', 'page'],
  dnsfilter_get_top_users: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'page'],
  dnsfilter_get_total_applications_agents_stats: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_total_applications_collections_stats: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_total_applications_networks_stats: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_total_applications_stats: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'msp_id', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_total_applications_users_stats: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'application_category_ids', 'name', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report'],
  dnsfilter_get_total_categories: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'],
  dnsfilter_get_total_categories_organizations: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_organizations'],
  dnsfilter_get_total_category_stats: ['from', 'to', 'organization_id', 'network_ids', 'category_ids', 'msp_id'],
  dnsfilter_get_total_client_stats: ['from', 'to', 'organization_id', 'network_ids', 'msp_id'],
  dnsfilter_get_total_deployments: ['organization_id', 'network_ids', 'msp_id'],
  dnsfilter_get_total_domain_stats: ['from', 'to', 'organization_id', 'network_ids', 'domain', 'fqdn', 'msp_id'],
  dnsfilter_get_total_domains: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'],
  dnsfilter_get_total_domains_organizations: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_organizations'],
  dnsfilter_get_total_domains_users: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_users'],
  dnsfilter_get_total_organizations_requests: ['from', 'to', 'organization_ids', 'organization_id', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'collection_ids', 'application_ids', 'category_ids', 'domain', 'fqdn', 'msp_id', 'name', 'type', 'security_report', 'bucket_size'],
  dnsfilter_get_total_organizations_stats: ['from', 'to', 'organization_id', 'agent_ids', 'agent_types', 'user_ids', 'collection_ids', 'application_category_ids', 'msp_id', 'name', 'type', 'security_report', 'bucket_size'],
  dnsfilter_get_total_requests: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_networks'],
  dnsfilter_get_total_requests_agents: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_agents'],
  dnsfilter_get_total_requests_collections: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_collections'],
  dnsfilter_get_total_requests_geo: ['from', 'to', 'organization_ids', 'msp_id', 'limit'],
  dnsfilter_get_total_requests_organizations: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_organizations'],
  dnsfilter_get_total_requests_users: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'nat_ips', 'collection_ids', 'application_ids', 'msp_id', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'security_report', 'bucket_size', 'show_individual_users'],
  dnsfilter_get_total_roaming_clients: ['organization_id', 'msp_id'],
  dnsfilter_get_total_threats: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'bucket_size', 'show_individual_networks'],
  dnsfilter_get_total_threats_organizations: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'bucket_size', 'show_individual_organizations'],
  dnsfilter_get_total_threats_users: ['from', 'to', 'organization_ids', 'network_ids', 'agent_ids', 'agent_types', 'user_ids', 'mac_addresses', 'collection_ids', 'application_ids', 'private_ip', 'private_ip_from', 'private_ip_to', 'type', 'source', 'bucket_size', 'show_individual_users'],
};

export async function handleTrafficReportTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  const fn = CLIENT_FN[name];
  const allowedKeys = TOOL_PARAM_KEYS[name];
  if (!fn || !allowedKeys) return errorResult(`Unknown tool: ${name}`);

  try {
    const params: Record<string, unknown> = {};
    for (const key of allowedKeys) {
      if (args[key] !== undefined) params[key] = args[key];
    }
    return textResult(await fn(creds!, params));
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
