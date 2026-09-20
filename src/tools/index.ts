import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { BLOCK_PAGE_TOOLS, handleBlockPageTool, isBlockPageTool } from './block-pages.js';
import { CATEGORY_TOOLS, handleCategoryTool, isCategoryTool } from './categories.js';
import { handleMetricsTool, isMetricsTool, METRICS_TOOLS } from './metrics.js';
import { handleNetworkTool, isNetworkTool, NETWORK_TOOLS } from './networks.js';
import { handleOrganizationTool, isOrganizationTool, ORGANIZATION_TOOLS } from './organizations.js';
import { handlePolicyTool, isPolicyTool, POLICY_TOOLS } from './policies.js';
import { handleTrafficReportTool, isTrafficReportTool, TRAFFIC_REPORT_TOOLS } from './traffic-reports.js';
import type { CallToolResult } from './types.js';

export const ALL_TOOLS: Tool[] = [
  ...ORGANIZATION_TOOLS,
  ...NETWORK_TOOLS,
  ...POLICY_TOOLS,
  ...CATEGORY_TOOLS,
  ...BLOCK_PAGE_TOOLS,
  ...METRICS_TOOLS,
  ...TRAFFIC_REPORT_TOOLS,
];

export async function dispatchToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  if (isOrganizationTool(name)) return handleOrganizationTool(name, args);
  if (isNetworkTool(name)) return handleNetworkTool(name, args);
  if (isPolicyTool(name)) return handlePolicyTool(name, args);
  if (isCategoryTool(name)) return handleCategoryTool(name, args);
  if (isBlockPageTool(name)) return handleBlockPageTool(name, args);
  if (isMetricsTool(name)) return handleMetricsTool(name, args);
  if (isTrafficReportTool(name)) return handleTrafficReportTool(name, args);
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}
