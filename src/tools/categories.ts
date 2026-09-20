import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getApplicationCategory,
  getCategory,
  getCredentials,
  listApplicationCategories,
  listCategories,
} from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const CATEGORY_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_list_categories',
    description:
      "List DNSFilter's content-filtering categories (e.g. Malware, Gambling, Social Networking) used to build allow/block rules in a policy. Category IDs from this response are required by dnsfilter_get_category and can filter traffic-report tools via category_ids.",
    inputSchema: { type: 'object', properties: { ...PAGE_PARAMS_PROPERTIES } },
  },
  {
    name: 'dnsfilter_get_category',
    description: "Get one content category's details and hierarchy (parent/child categories). Requires a category ID from dnsfilter_list_categories.",
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'number', description: 'Category ID, from dnsfilter_list_categories.' } },
      required: ['id'],
    },
  },
  {
    name: 'dnsfilter_list_application_categories',
    description:
      "List application categories, used for the application allow/block surface of a policy (distinct from content categories). IDs from this response are required by dnsfilter_get_application_category and can filter traffic-report tools via application_category_ids.",
    inputSchema: { type: 'object', properties: { ...PAGE_PARAMS_PROPERTIES } },
  },
  {
    name: 'dnsfilter_get_application_category',
    description: "Get one application category's details. Requires an application category ID from dnsfilter_list_application_categories.",
    inputSchema: {
      type: 'object',
      properties: { id: { type: 'number', description: 'Application category ID, from dnsfilter_list_application_categories.' } },
      required: ['id'],
    },
  },
];

const TOOL_NAMES = new Set(CATEGORY_TOOLS.map((t) => t.name));
export function isCategoryTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleCategoryTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'dnsfilter_list_categories') {
      return textResult(await listCategories(creds!, { page: args.page as { number?: number; size?: number } | undefined }));
    }

    if (name === 'dnsfilter_get_category') {
      return textResult(await getCategory(creds!, args.id as number));
    }

    if (name === 'dnsfilter_list_application_categories') {
      return textResult(
        await listApplicationCategories(creds!, { page: args.page as { number?: number; size?: number } | undefined })
      );
    }

    if (name === 'dnsfilter_get_application_category') {
      return textResult(await getApplicationCategory(creds!, args.id as number));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
