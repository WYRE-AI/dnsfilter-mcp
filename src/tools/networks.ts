import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getNetwork, getNetworksGeo, listNetworks, lookupNetworkByIp } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const NETWORK_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_list_networks',
    description:
      'List the networks (sites/locations) visible to this API key, with basic info and whether a filtering policy is assigned. Network IDs from this response are required by dnsfilter_get_network and can scope most traffic-report tools via network_ids.',
    inputSchema: {
      type: 'object',
      properties: {
        basic_info: { type: 'boolean', description: 'Return only the most basic network info. Defaults to false.' },
        count_network_ips: { type: 'boolean', description: 'Include a count of associated IP addresses. Defaults to false.' },
        force_truncate_ips: { type: 'boolean', description: 'Omit IP address details from the response. Defaults to false.' },
        protected: { type: 'boolean', description: 'Filter to networks with an assigned policy.' },
        unprotected: { type: 'boolean', description: 'Filter to networks without an assigned policy.' },
        search: { type: 'string', description: 'Search by network name, hostname, IP address, etc.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'dnsfilter_get_network',
    description: "Get one network's basic information. Requires a network ID from dnsfilter_list_networks.",
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Network ID, from dnsfilter_list_networks.' },
        count_network_ips: { type: 'boolean', description: 'Include a count of associated IP addresses. Defaults to false.' },
      },
      required: ['id'],
    },
  },
  {
    name: 'dnsfilter_lookup_network_by_ip',
    description: 'Find the network associated with a given source IP address, along with that network\'s block-page branding.',
    inputSchema: {
      type: 'object',
      properties: {
        requesting_ip_address: { type: 'string', description: 'IP address to look up.' },
      },
      required: ['requesting_ip_address'],
    },
  },
  {
    name: 'dnsfilter_get_networks_geo',
    description: "Get every visible network's geo/location metadata only (name, lat/long, physical address) - a lighter-weight variant of dnsfilter_list_networks for mapping.",
    inputSchema: { type: 'object', properties: {} },
  },
];

const TOOL_NAMES = new Set(NETWORK_TOOLS.map((t) => t.name));
export function isNetworkTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleNetworkTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'dnsfilter_list_networks') {
      return textResult(
        await listNetworks(creds!, {
          basic_info: args.basic_info as boolean | undefined,
          count_network_ips: args.count_network_ips as boolean | undefined,
          force_truncate_ips: args.force_truncate_ips as boolean | undefined,
          protected: args.protected as boolean | undefined,
          unprotected: args.unprotected as boolean | undefined,
          search: args.search as string | undefined,
          page: args.page as { number?: number; size?: number } | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_network') {
      return textResult(
        await getNetwork(creds!, {
          id: args.id as number,
          count_network_ips: args.count_network_ips as boolean | undefined,
        })
      );
    }

    if (name === 'dnsfilter_lookup_network_by_ip') {
      return textResult(
        await lookupNetworkByIp(creds!, {
          requesting_ip_address: args.requesting_ip_address as string,
        })
      );
    }

    if (name === 'dnsfilter_get_networks_geo') {
      return textResult(await getNetworksGeo(creds!));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
