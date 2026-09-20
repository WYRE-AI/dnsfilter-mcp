import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getApplicationPolicies, getCredentials, getPolicy, getPolicyPermissiveMode, listPolicies } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const POLICY_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_list_policies',
    description:
      'List filtering policies visible to this API key. Policy IDs from this response are required by dnsfilter_get_policy and dnsfilter_get_policy_permissive_mode.',
    inputSchema: {
      type: 'object',
      properties: {
        organization_id: { type: 'number', description: 'Filter to policies belonging to this organization.' },
        include_global_policies: { type: 'boolean', description: 'Include global (template) policies in the listing.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'dnsfilter_get_policy',
    description:
      "Get one policy's full configuration: allow/block domain lists, allow/block category rules, allowed/blocked applications, and which networks it's assigned to. Requires a policy ID from dnsfilter_list_policies.",
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Policy ID, from dnsfilter_list_policies.' },
        include_relationships: { type: 'boolean', description: 'Include related resources (organization, networks) in the response. Defaults to true.' },
      },
      required: ['id'],
    },
  },
  {
    name: 'dnsfilter_get_application_policies',
    description: "Get which policies in an organization allow or block a specific application. Requires an application ID and organization ID.",
    inputSchema: {
      type: 'object',
      properties: {
        application_id: { type: 'number', description: 'Application ID to look up.' },
        organization_id: { type: 'number', description: 'Organization ID to scope the search to.' },
        name: { type: 'string', description: 'Filter to policies whose name matches (or partially matches).' },
        policy_ids: { type: 'array', items: { type: 'number' }, description: 'Limit the search to these policy IDs.' },
      },
      required: ['application_id', 'organization_id'],
    },
  },
  {
    name: 'dnsfilter_get_policy_permissive_mode',
    description: "Get whether a policy currently has permissive (monitor-only, non-blocking) mode enabled. Requires a policy ID from dnsfilter_list_policies.",
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Policy ID, from dnsfilter_list_policies.' },
      },
      required: ['id'],
    },
  },
];

const TOOL_NAMES = new Set(POLICY_TOOLS.map((t) => t.name));
export function isPolicyTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handlePolicyTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'dnsfilter_list_policies') {
      return textResult(
        await listPolicies(creds!, {
          organization_id: args.organization_id as number | undefined,
          include_global_policies: args.include_global_policies as boolean | undefined,
          page: args.page as { number?: number; size?: number } | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_policy') {
      return textResult(
        await getPolicy(creds!, {
          id: args.id as number,
          include_relationships: args.include_relationships as boolean | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_application_policies') {
      return textResult(
        await getApplicationPolicies(creds!, {
          application_id: args.application_id as number,
          organization_id: args.organization_id as number,
          name: args.name as string | undefined,
          policy_ids: args.policy_ids as number[] | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_policy_permissive_mode') {
      return textResult(await getPolicyPermissiveMode(creds!, { id: args.id as number }));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
