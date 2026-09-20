import { describe, expect, it } from 'vitest';
import { ALL_TOOLS } from '../tools/index.js';

/**
 * Hard scope boundary (see README's Scope section): this connector must
 * NEVER expose a tool that mutates/provisions/deletes anything, or that
 * goes outside DNSFilter's documented orgs / networks / policies /
 * categories / block-pages / reporting surface. Pin the exact tool set so
 * an accidental addition - a copy-pasted "create_policy", "delete_network",
 * "update_organization", or any tool outside those six resource groups -
 * fails this test immediately rather than silently shipping.
 */
describe('ALL_TOOLS scope boundary', () => {
  const EXPECTED_TOOL_NAMES = [
    // Organizations
    'dnsfilter_list_organizations',
    'dnsfilter_get_organization',
    'dnsfilter_get_organization_settings',
    // Networks
    'dnsfilter_list_networks',
    'dnsfilter_get_network',
    'dnsfilter_lookup_network_by_ip',
    'dnsfilter_get_networks_geo',
    // Policies
    'dnsfilter_list_policies',
    'dnsfilter_get_policy',
    'dnsfilter_get_application_policies',
    'dnsfilter_get_policy_permissive_mode',
    // Categories
    'dnsfilter_list_categories',
    'dnsfilter_get_category',
    'dnsfilter_list_application_categories',
    'dnsfilter_get_application_category',
    // Block Pages
    'dnsfilter_list_block_pages',
    'dnsfilter_get_block_page',
    // Metrics
    'dnsfilter_get_organization_usage',
    'dnsfilter_get_organization_usage_detailed',
    // Traffic Reports
    'dnsfilter_get_qps',
    'dnsfilter_get_qps_active_agents',
    'dnsfilter_get_qps_active_organizations',
    'dnsfilter_get_query_logs',
    'dnsfilter_get_top_agents',
    'dnsfilter_get_top_application_categories',
    'dnsfilter_get_top_categories',
    'dnsfilter_get_top_collections',
    'dnsfilter_get_top_domains',
    'dnsfilter_get_top_networks',
    'dnsfilter_get_top_organizations_requests',
    'dnsfilter_get_top_users',
    'dnsfilter_get_total_applications_agents_stats',
    'dnsfilter_get_total_applications_collections_stats',
    'dnsfilter_get_total_applications_networks_stats',
    'dnsfilter_get_total_applications_stats',
    'dnsfilter_get_total_applications_users_stats',
    'dnsfilter_get_total_categories',
    'dnsfilter_get_total_categories_organizations',
    'dnsfilter_get_total_category_stats',
    'dnsfilter_get_total_client_stats',
    'dnsfilter_get_total_deployments',
    'dnsfilter_get_total_domain_stats',
    'dnsfilter_get_total_domains',
    'dnsfilter_get_total_domains_organizations',
    'dnsfilter_get_total_domains_users',
    'dnsfilter_get_total_organizations_requests',
    'dnsfilter_get_total_organizations_stats',
    'dnsfilter_get_total_requests',
    'dnsfilter_get_total_requests_agents',
    'dnsfilter_get_total_requests_collections',
    'dnsfilter_get_total_requests_geo',
    'dnsfilter_get_total_requests_organizations',
    'dnsfilter_get_total_requests_users',
    'dnsfilter_get_total_roaming_clients',
    'dnsfilter_get_total_threats',
    'dnsfilter_get_total_threats_organizations',
    'dnsfilter_get_total_threats_users',
  ].sort();

  it("exposes exactly this connector's 57 read-only tools - nothing more, nothing less", () => {
    const names = ALL_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(EXPECTED_TOOL_NAMES);
    expect(names).toHaveLength(57);
  });

  it('never exposes a write, delete, or provisioning tool', () => {
    // Forbidden as a whole underscore-token, not a substring, so this does
    // NOT false-positive on tokens like 'settings' or 'collections'.
    // DNSFilter's own documented write surface (policies, networks,
    // organizations, block pages, API keys, users, etc. all have real
    // POST/PATCH/DELETE operations) is entirely excluded from this
    // connector by construction - see client.ts, which contains zero
    // POST/PUT/PATCH/DELETE calls anywhere.
    const FORBIDDEN_TOKENS = new Set([
      'create', 'update', 'delete', 'add', 'set', 'edit', 'remove', 'resolve',
      'revoke', 'reset', 'assign', 'rotate', 'generate', 'promote', 'cancel',
      'bulk', 'destroy', 'suggest', 'dequeue', 'resend',
    ]);

    for (const tool of ALL_TOOLS) {
      const tokens = tool.name.split('_');
      for (const token of tokens) {
        expect(
          FORBIDDEN_TOKENS.has(token),
          `Tool "${tool.name}" contains forbidden token "${token}" - this connector must stay read-only.`
        ).toBe(false);
      }
    }
  });

  it('every tool name is prefixed with dnsfilter_', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.name.startsWith('dnsfilter_')).toBe(true);
    }
  });

  it('every tool has a non-empty description and an object inputSchema', () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.description, `Tool "${tool.name}" has no description`).toBeTruthy();
      expect(tool.inputSchema?.type).toBe('object');
    }
  });
});
