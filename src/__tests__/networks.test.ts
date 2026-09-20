import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleNetworkTool } from '../tools/networks.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleNetworkTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dnsfilter_list_networks forwards protected/unprotected/search filters', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ id: '1' }] }));

    const result = await runWithCredentials(creds, () =>
      handleNetworkTool('dnsfilter_list_networks', { protected: true, search: 'hq' })
    );

    expect(result.isError).toBeUndefined();
    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/networks');
    expect(url.searchParams.get('protected')).toBe('true');
    expect(url.searchParams.get('search')).toBe('hq');
  });

  it('dnsfilter_get_network scopes the request to the network ID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { id: '9' } }));

    await runWithCredentials(creds, () => handleNetworkTool('dnsfilter_get_network', { id: 9 }));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/networks/9');
  });

  it('dnsfilter_lookup_network_by_ip requires and forwards requesting_ip_address', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ block_org_name: 'Acme' }));

    await runWithCredentials(creds, () =>
      handleNetworkTool('dnsfilter_lookup_network_by_ip', { requesting_ip_address: '203.0.113.5' })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/networks/lookup');
    expect(url.searchParams.get('requesting_ip_address')).toBe('203.0.113.5');
  });

  it('dnsfilter_get_networks_geo hits the geo endpoint with no query params', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse([{ id: 1, latitude: 1.2, longitude: 3.4 }]));

    const result = await runWithCredentials(creds, () => handleNetworkTool('dnsfilter_get_networks_geo', {}));

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/networks/geo');
    expect(url.search).toBe('');
    expect(JSON.parse(textOf(result))[0].latitude).toBe(1.2);
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleNetworkTool('dnsfilter_list_networks', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
