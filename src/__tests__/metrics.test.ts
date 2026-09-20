import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleMetricsTool } from '../tools/metrics.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleMetricsTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dnsfilter_get_organization_usage scopes to the org ID and forwards the date range', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { organization_id: 1, total_requests: 100 } }));

    const result = await runWithCredentials(creds, () =>
      handleMetricsTool('dnsfilter_get_organization_usage', { id: 1, from: '2026-08-01', to: '2026-09-01' })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/metrics/organization_usage/1');
    expect(url.searchParams.get('from')).toBe('2026-08-01');
    expect(url.searchParams.get('to')).toBe('2026-09-01');
    expect(JSON.parse(textOf(result)).data.total_requests).toBe(100);
  });

  it('dnsfilter_get_organization_usage_detailed scopes to the org ID and forwards the date range', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: {} }));

    await runWithCredentials(creds, () =>
      handleMetricsTool('dnsfilter_get_organization_usage_detailed', { id: 9, from: '2026-01-01', to: '2026-01-31' })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/metrics/organization_usage_detailed/9');
    expect(url.searchParams.get('from')).toBe('2026-01-01');
    expect(url.searchParams.get('to')).toBe('2026-01-31');
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleMetricsTool('dnsfilter_get_organization_usage', { id: 1, from: 'x', to: 'y' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
