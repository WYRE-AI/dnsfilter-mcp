import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getOrganization, getOrganizationSettings, listOrganizations } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const ORGANIZATION_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_list_organizations',
    description:
      'List the organizations visible to this API key, with basic info (name, type, MSP relationships). Organization IDs from this response are required by dnsfilter_get_organization, dnsfilter_list_networks/policies/block_pages (via organization_id), and every traffic-report tool.',
    inputSchema: {
      type: 'object',
      properties: {
        basic_info: { type: 'boolean', description: 'Return only the most basic organization info. Defaults to false.' },
        exclude_inherit_privacy_mode: { type: 'boolean', description: 'Exclude organizations that have inherit privacy mode.' },
        managed_by_msp_id: { type: 'number', description: "Filter to sub-organizations managed by this MSP's ID." },
        name: { type: 'string', description: 'Filter by organization name.' },
        owned_msp_id: { type: 'number', description: "Filter to parent organizations owned by this MSP's ID." },
        pii_grid_search: { type: 'string', description: 'Filter by organization name or privacy mode.' },
        type: { type: 'string', enum: ['normal', 'msp', 'sub_organization'], description: 'Filter by organization type.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'dnsfilter_get_organization',
    description: "Get one organization's basic information. Requires an organization ID from dnsfilter_list_organizations.",
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Organization ID, from dnsfilter_list_organizations.' },
        include_current_mrr: { type: 'boolean', description: 'Include current MRR (monthly recurring revenue) information.' },
      },
      required: ['id'],
    },
  },
  {
    name: 'dnsfilter_get_organization_settings',
    description: 'Get organization-level settings, optionally scoped to a specific organization or MSP.',
    inputSchema: {
      type: 'object',
      properties: {
        organization_id: { type: 'number', description: 'Organization ID to scope to.' },
        organization_ids: { type: 'string', description: 'Comma-separated organization IDs to scope to.' },
        msp_id: { type: 'number', description: 'MSP ID to scope to.' },
        name: { type: 'string', description: 'Filter by organization name.' },
      },
    },
  },
];

const TOOL_NAMES = new Set(ORGANIZATION_TOOLS.map((t) => t.name));
export function isOrganizationTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleOrganizationTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'dnsfilter_list_organizations') {
      return textResult(
        await listOrganizations(creds!, {
          basic_info: args.basic_info as boolean | undefined,
          exclude_inherit_privacy_mode: args.exclude_inherit_privacy_mode as boolean | undefined,
          managed_by_msp_id: args.managed_by_msp_id as number | undefined,
          name: args.name as string | undefined,
          owned_msp_id: args.owned_msp_id as number | undefined,
          pii_grid_search: args.pii_grid_search as string | undefined,
          type: args.type as 'normal' | 'msp' | 'sub_organization' | undefined,
          page: args.page as { number?: number; size?: number } | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_organization') {
      return textResult(
        await getOrganization(creds!, {
          id: args.id as number,
          include_current_mrr: args.include_current_mrr as boolean | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_organization_settings') {
      return textResult(
        await getOrganizationSettings(creds!, {
          organization_id: args.organization_id as number | undefined,
          organization_ids: args.organization_ids as string | undefined,
          msp_id: args.msp_id as number | undefined,
          name: args.name as string | undefined,
        })
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
