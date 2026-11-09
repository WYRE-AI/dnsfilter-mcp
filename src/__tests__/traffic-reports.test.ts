import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../utils/logger.js';
import { DNSFilterApiError } from '../types.js';
import { getTotalClientStats } from '../client.js';
import { handleTrafficReportTool, TRAFFIC_REPORT_TOOLS } from '../tools/traffic-reports.js';
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
    vi.restoreAllMocks();
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

  it.each(['dnsfilter_get_qps_active_agents', 'dnsfilter_get_qps_active_organizations'])(
    '%s excludes undocumented filters from its schema and request', async (tool) => {
      const extras = ['mac_addresses', 'nat_ips', 'private_ip', 'private_ip_from', 'private_ip_to'];
      fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));
      await runWithCredentials(creds, () => handleTrafficReportTool(
        tool, Object.fromEntries(extras.map(key => [key, 'unsupported']))
      ));
      const url = new URL(fetchMock.mock.calls[0][0]);
      const schema = TRAFFIC_REPORT_TOOLS.find(entry => entry.name === tool)!.inputSchema;
      for (const key of extras) {
        expect(url.searchParams.has(key)).toBe(false);
        expect(schema.properties).not.toHaveProperty(key);
      }
    }
  );

  it('omits empty and whitespace-only documented query values', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));
    await runWithCredentials(creds, () => handleTrafficReportTool(
      'dnsfilter_get_qps_active_agents', { organization_ids: '', from: ' \t\n' }
    ));
    expect(new URL(fetchMock.mock.calls[0][0]).search).toBe('');
  });

  it.each(['plain text', 'json'])('surfaces a redacted 400 %s body and logs it', async (format) => {
    const logSpy = vi.spyOn(logger, 'error').mockImplementation(() => {});
    const token = 'a'.repeat(60);
    const detail = `Invalid date\n ${creds.apiKey} Bearer short-token eyJhbGci.eyJzdWI.signature ${token}`;
    fetchMock.mockResolvedValueOnce(new Response(
      format === 'json' ? JSON.stringify({ detail }) : detail, { status: 400 }
    ));
    const result = await runWithCredentials(creds, () => handleTrafficReportTool(
      'dnsfilter_get_total_client_stats', {}
    ));
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain('HTTP 400');
    expect(textOf(result)).toContain('Invalid date');
    expect(textOf(result)).not.toContain(creds.apiKey);
    expect(textOf(result)).not.toContain(token);
    expect(textOf(result)).not.toContain('short-token');
    expect(textOf(result)).not.toContain('eyJhbGci');
    expect(logSpy).toHaveBeenCalledWith('DNSFilter upstream error', expect.objectContaining({
      status: 400, path: '/v1/traffic_reports/total_client_stats',
      body: expect.stringContaining('[redacted]'),
    }));
    expect(JSON.stringify(logSpy.mock.calls)).not.toContain(creds.apiKey);
  });

  it('bounds error previews and tolerates unreadable error bodies', async () => {
    const logSpy = vi.spyOn(logger, 'error').mockImplementation(() => {});
    fetchMock.mockResolvedValueOnce(new Response('invalid '.repeat(100), { status: 500 }));
    await expect(getTotalClientStats(creds)).rejects.toMatchObject({ status: 500 });
    expect((logSpy.mock.calls[0][1] as { body: string }).body).toHaveLength(500);
    fetchMock.mockResolvedValueOnce({ status: 400, ok: false, text: vi.fn().mockRejectedValue(new Error('read failed')) });
    await expect(getTotalClientStats(creds)).rejects.toThrow('failed: HTTP 400');
  });

  it.each([
    ['dnsfilter_get_query_logs', 25_000],
    ['dnsfilter_get_total_client_stats', 15_000],
  ] as const)('%s uses a %i ms timeout', async (tool, timeoutMs) => {
    const timeoutSpy = vi.spyOn(AbortSignal, 'timeout');
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));
    await runWithCredentials(creds, () => handleTrafficReportTool(tool, {}));
    expect(timeoutSpy).toHaveBeenCalledTimes(1);
    expect(timeoutSpy).toHaveBeenCalledWith(timeoutMs);
  });

  it.each(['AbortError', 'TimeoutError'])('turns %s into a clear API error', async (name) => {
    fetchMock.mockRejectedValueOnce(new DOMException('aborted', name));
    const error = await getTotalClientStats(creds).catch(err => err);
    expect(error).toBeInstanceOf(DNSFilterApiError);
    expect(error.message).toBe('DNSFilter /v1/traffic_reports/total_client_stats timed out after 15000ms');
    expect(error.status).toBeUndefined();
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
