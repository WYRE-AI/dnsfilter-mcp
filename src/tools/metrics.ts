import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getOrganizationUsage, getOrganizationUsageDetailed } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, requireCredentials, textResult } from './shared.js';

const FROM_TO_PROPERTIES = {
  id: { type: 'number', description: 'Organization ID, from dnsfilter_list_organizations.' },
  from: { type: 'string', format: 'date', description: 'Range start date, ISO 8601 (e.g. "2026-08-01").' },
  to: { type: 'string', format: 'date', description: 'Range end date, ISO 8601 (e.g. "2026-09-01"). Maximum range is 365 days.' },
} as const;

export const METRICS_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_get_organization_usage',
    description:
      "Get usage information (plan, term, user/wifi counts, total requests, estimated users) for an organization over a date range. Maximum range is 365 days. Requires an organization ID from dnsfilter_list_organizations.",
    inputSchema: { type: 'object', properties: { ...FROM_TO_PROPERTIES }, required: ['id', 'from', 'to'] },
  },
  {
    name: 'dnsfilter_get_organization_usage_detailed',
    description:
      "Get the detailed (per-metric) breakdown of an organization's usage over a date range. Maximum range is 365 days. Requires an organization ID from dnsfilter_list_organizations.",
    inputSchema: { type: 'object', properties: { ...FROM_TO_PROPERTIES }, required: ['id', 'from', 'to'] },
  },
];

const TOOL_NAMES = new Set(METRICS_TOOLS.map((t) => t.name));
export function isMetricsTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleMetricsTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    const params = { id: args.id as number, from: args.from as string, to: args.to as string };

    if (name === 'dnsfilter_get_organization_usage') {
      return textResult(await getOrganizationUsage(creds!, params));
    }

    if (name === 'dnsfilter_get_organization_usage_detailed') {
      return textResult(await getOrganizationUsageDetailed(creds!, params));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
