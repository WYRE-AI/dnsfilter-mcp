import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleOrganizationTool } from '../tools/organizations.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleOrganizationTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dnsfilter_list_organizations sends the raw API key (no Bearer prefix) and forwards filters', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ id: '1', type: 'organizations' }] }));

    const result = await runWithCredentials(creds, () =>
      handleOrganizationTool('dnsfilter_list_organizations', { type: 'msp', name: 'Acme' })
    );

    expect(result.isError).toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(new URL(url).pathname).toBe('/v1/organizations');
    expect(new URL(url).searchParams.get('type')).toBe('msp');
    expect(new URL(url).searchParams.get('name')).toBe('Acme');
    expect((init.headers as Record<string, string>).Authorization).toBe('key-1');
    expect(JSON.parse(textOf(result)).data[0].id).toBe('1');
  });

  it('dnsfilter_list_organizations encodes nested pagination as page[number]/page[size]', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));

    await runWithCredentials(creds, () =>
      handleOrganizationTool('dnsfilter_list_organizations', { page: { number: 2, size: 25 } })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.searchParams.get('page[number]')).toBe('2');
    expect(url.searchParams.get('page[size]')).toBe('25');
  });

  it('dnsfilter_get_organization scopes the request to the organization ID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { id: '42' } }));

    const result = await runWithCredentials(creds, () =>
      handleOrganizationTool('dnsfilter_get_organization', { id: 42, include_current_mrr: true })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/organizations/42');
    expect(url.searchParams.get('include_current_mrr')).toBe('true');
    expect(result.isError).toBeUndefined();
  });

  it('dnsfilter_get_organization_settings forwards scoping params', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: {} }));

    await runWithCredentials(creds, () =>
      handleOrganizationTool('dnsfilter_get_organization_settings', { organization_id: 7, msp_id: 3 })
    );

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe('/v1/organizations/settings');
    expect(url.searchParams.get('organization_id')).toBe('7');
    expect(url.searchParams.get('msp_id')).toBe('3');
  });

  it('surfaces a 401 as a readable auth error rather than throwing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'unauthorized' }, 401));

    const result = await runWithCredentials(creds, () =>
      handleOrganizationTool('dnsfilter_list_organizations', {})
    );

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/rejected the API key/i);
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleOrganizationTool('dnsfilter_list_organizations', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
