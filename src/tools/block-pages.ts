import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getBlockPage, getCredentials, listBlockPages } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const BLOCK_PAGE_TOOLS: Tool[] = [
  {
    name: 'dnsfilter_list_block_pages',
    description:
      'List the custom block pages configured for the current user/organization (shown to end users when a request is filtered). Block page IDs from this response are required by dnsfilter_get_block_page.',
    inputSchema: {
      type: 'object',
      properties: {
        organization_id: { type: 'number', description: 'Filter to block pages belonging to this organization.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'dnsfilter_get_block_page',
    description:
      "Get one custom block page's configuration: branding (org name, logo), contact email, and appearance settings. Requires a block page ID from dnsfilter_list_block_pages.",
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'number', description: 'Block page ID, from dnsfilter_list_block_pages.' },
        include_relationships: { type: 'boolean', description: 'Include related resources in the response. Defaults to true.' },
      },
      required: ['id'],
    },
  },
];

const TOOL_NAMES = new Set(BLOCK_PAGE_TOOLS.map((t) => t.name));
export function isBlockPageTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleBlockPageTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'dnsfilter_list_block_pages') {
      return textResult(
        await listBlockPages(creds!, {
          organization_id: args.organization_id as number | undefined,
          page: args.page as { number?: number; size?: number } | undefined,
        })
      );
    }

    if (name === 'dnsfilter_get_block_page') {
      return textResult(
        await getBlockPage(creds!, {
          id: args.id as number,
          include_relationships: args.include_relationships as boolean | undefined,
        })
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
