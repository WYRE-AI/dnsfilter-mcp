import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleCategoryTool } from '../tools/categories.js';
import { runWithCredentials } from '../client.js';
import { jsonResponse, textOf } from './test-helpers.js';

describe('handleCategoryTool', () => {
  const fetchMock = vi.fn();
  const creds = { apiKey: 'key-1' };

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('dnsfilter_list_categories hits /v1/categories', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [{ id: '1', attributes: { name: 'Malware' } }] }));

    const result = await runWithCredentials(creds, () => handleCategoryTool('dnsfilter_list_categories', {}));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/categories');
    expect(result.isError).toBeUndefined();
  });

  it('dnsfilter_get_category scopes the request to the category ID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { id: '4' } }));

    await runWithCredentials(creds, () => handleCategoryTool('dnsfilter_get_category', { id: 4 }));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/categories/4');
  });

  it('dnsfilter_list_application_categories hits /v1/application_categories', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }));

    await runWithCredentials(creds, () => handleCategoryTool('dnsfilter_list_application_categories', {}));

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/application_categories');
  });

  it('dnsfilter_get_application_category scopes the request to the application category ID in the path', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { id: '6' } }));

    const result = await runWithCredentials(creds, () =>
      handleCategoryTool('dnsfilter_get_application_category', { id: 6 })
    );

    expect(new URL(fetchMock.mock.calls[0][0] as string).pathname).toBe('/v1/application_categories/6');
    expect(JSON.parse(textOf(result)).data.id).toBe('6');
  });

  it('returns a credential error without calling fetch when no key is configured', async () => {
    const result = await handleCategoryTool('dnsfilter_list_categories', {});

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/DNSFILTER_API_KEY/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
