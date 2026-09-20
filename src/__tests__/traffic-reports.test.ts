import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleTrafficReportTool } from '../tools/traffic-reports.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

/**
 * One test per /v1/traffic_reports/* tool (see traffic-reports.ts's own
 * header comment): each case asserts the tool hits the right path and
 * forwards one representative documented param, so a future edit that
 * swaps two tools' paths or drops a param from TOOL_PARAM_KEYS fails
 * loudly instead of silently.
 */
describe('handleTrafficReportTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it.each([
    ['dnsfilter_get_qps', 'qps', 'organization_ids', '5'],
    ['dnsfilter_get_qps_active_agents', 'qps_active_agents', 'network_ids', '10'],
    ['dnsfilter_get_qps_active_organizations', 'qps_active_organizations', 'organization_ids', '5'],
    ['dnsfilter_get_query_logs', 'query_logs', 'organization_id', '5'],
    ['dnsfilter_get_top_agents', 'top_agents', 'organization_ids', '5'],
    ['dnsfilter_get_top_application_categories', 'top_application_categories', 'organization_ids', '5'],
    ['dnsfilter_get_top_categories', 'top_categories', 'organization_ids', '5'],
    ['dnsfilter_get_top_collections', 'top_collections', 'organization_ids', '5'],
    ['dnsfilter_get_top_domains', 'top_domains', 'domain', 'example.com'],
    ['dnsfilter_get_top_networks', 'top_networks', 'network_ids', '10'],
    ['dnsfilter_get_top_organizations_requests', 'top_organizations_requests', 'organization_id', '5'],
    ['dnsfilter_get_top_users', 'top_users', 'user_ids', '3'],
    ['dnsfilter_get_total_applications_agents_stats', 'total_applications_agents_stats', 'application_ids', '2'],
    ['dnsfilter_get_total_applications_collections_stats', 'total_applications_collections_stats', 'collection_ids', '1'],
    ['dnsfilter_get_total_applications_networks_stats', 'total_applications_networks_stats', 'network_ids', '10'],
    ['dnsfilter_get_total_applications_stats', 'total_applications_stats', 'organization_ids', '5'],
    ['dnsfilter_get_total_applications_users_stats', 'total_applications_users_stats', 'user_ids', '3'],
    ['dnsfilter_get_total_categories', 'total_categories', 'organization_ids', '5'],
    ['dnsfilter_get_total_categories_organizations', 'total_categories_organizations', 'show_individual_organizations', 'true'],
    ['dnsfilter_get_total_category_stats', 'total_category_stats', 'category_ids', '9'],
    ['dnsfilter_get_total_client_stats', 'total_client_stats', 'organization_id', '5'],
    ['dnsfilter_get_total_deployments', 'total_deployments', 'organization_id', '5'],
    ['dnsfilter_get_total_domain_stats', 'total_domain_stats', 'domain', 'example.com'],
    ['dnsfilter_get_total_domains', 'total_domains', 'domain', 'example.com'],
    ['dnsfilter_get_total_domains_organizations', 'total_domains_organizations', 'organization_ids', '5'],
    ['dnsfilter_get_total_domains_users', 'total_domains_users', 'user_ids', '3'],
    ['dnsfilter_get_total_organizations_requests', 'total_organizations_requests', 'organization_id', '5'],
    ['dnsfilter_get_total_organizations_stats', 'total_organizations_stats', 'organization_id', '5'],
    ['dnsfilter_get_total_requests', 'total_requests', 'organization_ids', '5'],
    ['dnsfilter_get_total_requests_agents', 'total_requests_agents', 'agent_ids', 'abc'],
    ['dnsfilter_get_total_requests_collections', 'total_requests_collections', 'collection_ids', '1'],
    ['dnsfilter_get_total_requests_geo', 'total_requests_geo', 'limit', '50'],
    ['dnsfilter_get_total_requests_organizations', 'total_requests_organizations', 'organization_ids', '5'],
    ['dnsfilter_get_total_requests_users', 'total_requests_users', 'user_ids', '3'],
    ['dnsfilter_get_total_roaming_clients', 'total_roaming_clients', 'organization_id', '5'],
    ['dnsfilter_get_total_threats', 'total_threats', 'organization_ids', '5'],
    ['dnsfilter_get_total_threats_organizations', 'total_threats_organizations', 'organization_ids', '5'],
    ['dnsfilter_get_total_threats_users', 'total_threats_users', 'user_ids', '3'],
  ] as const)('%s hits /v1/traffic_reports/%s and forwards %s', async (tool, suffix, param, value) => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));

    const result = await runWithCredentials(creds, () => handleTrafficReportTool(tool, { [param]: value }));

    expect(result.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new URL(url).pathname).toBe(`/v1/traffic_reports/${suffix}`);
    expect(new URL(url).searchParams.get(param)).toBe(value);
    expect((init.headers as Record<string, string>).Authorization).toBe('key-1');
  });

  it('dnsfilter_get_query_logs returns the raw query-log entries', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ data: [{ domain: 'example.com', result: 'blocked' }] })
    );

    const result = await runWithCredentials(creds, () =>
      handleTrafficReportTool('dnsfilter_get_query_logs', { domain: 'example.com' })
    );

    expect(JSON.parse(textOf(result)).data[0].result).toBe('blocked');
  });

  it('an unknown traffic-report tool name is rejected rather than silently no-op-ing', async () => {
    const result = await runWithCredentials(creds, () =>
      handleTrafficReportTool('dnsfilter_get_not_a_real_report', {})
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/Unknown tool/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleTrafficReportTool('dnsfilter_get_total_requests', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
